#!/usr/bin/env python3
"""
Playwright-based X.com scraper.

Usage:
    python scraper.py --hashtags bugbounty CVE --search-interval-mins 60
    python scraper.py --on-demand --query "bounty awarded >$5000"
"""

import asyncio
import json
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from urllib.parse import urlparse

import httpx
from playwright.async_api import async_playwright, Page

# ─── Config ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("bountyradar.scraper")

@dataclass
class ScraperConfig:
    # Search
    hashtags: List[str] = field(default_factory=lambda: [
        "BugBounty", "CyberSecurity", "InfoSec", "EthicalHacking",
        "Pentesting", "BugBountyTips", "WebSecurity", "Vulnerability",
        "AppSec", "RedTeam", "HackerOne", "Bugcrowd", "YesWeHack",
        "0day", "CVE", "exploit", "bugbountytips", "bugbountytip"
    ])
    keywords: List[str] = field(default_factory=lambda: [
        "bounty awarded", "payout", "disclosed", "writeup", "PoC",
        "proof of concept", "CVE", "disclosure", "responsible disclosure",
        "triage", "severity critical", "pwned", "bounty paid", "CVSS"
    ])
    search_mode: str = "top"  # "top" | "latest" | "people"
    search_interval_mins: int = 30
    max_tweets_per_search: int = 50

    # Auth
    x_auth_token: Optional[str] = None  # X.com auth_token cookie
    x_csrf_token: Optional[str] = None  # ct0 cookie

    # Storage
    db_path: str = "sentinel.db"

    # Scoring
    award_threshold_immediate: float = 1000.0  # $1,000
    score_threshold_immediate: float = 0.80
    reputable_authors: List[str] = field(default_factory=lambda: [
        "sehacure", "renaudragen", "samwcyo", "naglinagli", "hackerone",
        "bugcrowd", "yeswehack", "intigriti", "amonsecurity", "bogdantirca"
    ])
    min_award_for_cve_alert: float = 500.0


# ─── Data Models ───────────────────────────────────────────────────────

@dataclass
class TweetItem:
    tweet_id: str
    author_handle: str
    author_display_name: str
    text: str
    timestamp: datetime
    hashtags: List[str]
    links: List[str]
    media_urls: List[str]
    has_image: bool
    has_video: bool
    like_count: int
    retweet_count: int
    reply_count: int
    is_thread: bool
    thread_id: Optional[str]
    cve_ids: List[str]
    award_amount: Optional[float]
    confidence_score: float = 0.0
    source_query: str = ""


# ─── Scraper Engine ────────────────────────────────────────────────────

class XScraper:
    SEARCH_URL = "https://x.com/search?q={query}&src=typed_query&f={mode}"

    def __init__(self, config: ScraperConfig):
        self.config = config
        self.db = SQLiteStore(config.db_path)
        self.seen_ids: set = set()
        self._load_seen_ids()

    def _load_seen_ids(self):
        rows = self.db.execute("SELECT tweet_id FROM tweets")
        self.seen_ids = {r[0] for r in rows}

    def _build_search_query(self, since_days: int = 7) -> str:
        """Build an X.com advanced search query from config.
        since_days: only fetch tweets from the last N days.
        """
        clauses = []
        for ht in self.config.hashtags:
            clauses.append(f"#{ht}")
        for kw in self.config.keywords:
            clauses.append(f'"{kw}"')
        query = " OR ".join(clauses)
        since_date = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime('%Y-%m-%d')
        date_filter = f"since:{since_date}"
        exclude = "-filter:retweets -filter:replies lang:en"
        full_query = f"({query}) {date_filter} {exclude}" if clauses else f"{date_filter} {exclude}"
        return full_query.replace(" ", "%20").replace("#", "%23").replace('"', "%22")

    async def _navigate_and_extract(self, page: Page, query: str) -> List[dict]:
        """Navigate to X.com search and extract tweet data."""
        url = self.SEARCH_URL.format(query=query, mode=self.config.search_mode)
        log.info(f"Navigating to: {url}")
        await page.goto(url, wait_until="domcontentloaded", timeout=90000)

        # Wait for the page to render (X.com is an SPA)
        try:
            await page.wait_for_selector('div[data-testid="primaryColumn"]', timeout=20000)
            log.info("Primary column loaded")
        except:
            log.warning("Timed out waiting for primary column — likely login wall")
            page_text = await page.inner_text("body") if await page.query_selector("body") else ""
            log.warning(f"Page text (first 200): {page_text[:200]}")
            log.warning("X.com requires auth. Set auth_token and ct0 in config.yaml")
            log.warning("How to get tokens: 1) Log into x.com in browser 2) Open DevTools → Application → Cookies")
            log.warning("  Copy auth_token and ct0 values into config.yaml")
            try:
                await page.screenshot(path="data/x_login_wall.png")
                log.info("Screenshot saved to data/x_login_wall.png")
            except:
                pass
            return []

        await asyncio.sleep(3)

        tweets_raw = []
        for scroll in range(3):
            articles = await page.query_selector_all('article[data-testid="tweet"]')
            log.info(f"Scroll {scroll + 1}: {len(articles)} articles found")
            for article in articles:
                try:
                    data = await self._extract_tweet(article)
                    if data and data["tweet_id"] not in self.seen_ids:
                        tweets_raw.append(data)
                        self.seen_ids.add(data["tweet_id"])
                except Exception as e:
                    log.warning(f"Failed to extract tweet: {e}")
            if len(tweets_raw) >= self.config.max_tweets_per_search:
                break
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(2)
        return tweets_raw[: self.config.max_tweets_per_search]

    async def _extract_tweet(self, article) -> Optional[dict]:
        """Extract structured data from a tweet article element."""
        # Tweet ID from permalink
        time_el = await article.query_selector("time")
        if not time_el:
            return None
        timestamp_str = await time_el.get_attribute("datetime")
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))

        # Author handle
        handle_el = await article.query_selector('[data-testid="User-Name"] a')
        handle = ""
        if handle_el:
            href = await handle_el.get_attribute("href")
            handle = href.lstrip("/").split("/")[0] if href else ""

        # Display name
        name_el = await article.query_selector('[data-testid="User-Name"] span')
        display_name = await name_el.inner_text() if name_el else ""

        # Tweet text
        text_el = await article.query_selector('[data-testid="tweetText"]')
        text = await text_el.inner_text() if text_el else ""

        # Tweet ID from permalink
        permalink_el = await article.query_selector('a[href*="/status/"]')
        tweet_id = ""
        if permalink_el:
            href = await permalink_el.get_attribute("href")
            match = re.search(r"/status/(\d+)", href or "")
            if match:
                tweet_id = match.group(1)

        if not tweet_id:
            return None

        # Links
        links = []
        link_els = await article.query_selector_all('a[href*="http"]')
        for el in link_els:
            href = await el.get_attribute("href")
            if href and "x.com" not in href and "twitter.com" not in href:
                links.append(href)

        # Media
        media_urls = []
        img_els = await article.query_selector_all('img[src*="media"]')
        for img in img_els:
            src = await img.get_attribute("src")
            if src:
                media_urls.append(src)

        has_image = len(media_urls) > 0
        has_video = await article.query_selector("video") is not None

        # Engagement
        likes = await self._get_metric(article, "like")
        retweets = await self._get_metric(article, "retweet")
        replies = await self._get_metric(article, "reply")

        # Hashtags
        hashtags = re.findall(r"#(\w+)", text)

        # CVE IDs
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)

        # Award amount
        award_amount = self._extract_award_amount(text)

        # Thread detection
        thread_id = None
        is_thread = False
        thread_el = await article.query_selector('[data-testid="tweet"]')
        # Simplified thread detection: check if tweet is part of a thread
        if permalink_el:
            href = await permalink_el.get_attribute("href") or ""
            # If the tweet link contains a thread indicator
            if "/status/" in href:
                thread_match = re.search(r"/status/(\d+)", href)
                if thread_match:
                    thread_id = thread_match.group(1)

        return {
            "tweet_id": tweet_id,
            "author_handle": handle,
            "author_display_name": display_name,
            "text": text[:500],  # Trim to avoid token limits
            "timestamp": timestamp.isoformat(),
            "hashtags": list(set(hashtags)),
            "links": list(set(links)),
            "media_urls": media_urls,
            "has_image": has_image,
            "has_video": has_video,
            "like_count": likes,
            "retweet_count": retweets,
            "reply_count": replies,
            "is_thread": is_thread,
            "thread_id": thread_id,
            "cve_ids": cve_ids,
            "award_amount": award_amount,
            "source_query": "",
        }

    async def _get_metric(self, article, metric_type: str) -> int:
        """Get engagement metric (like, retweet, reply) from a tweet."""
        try:
            selector = f'[data-testid="{metric_type}"] span[data-testid="app-text-transition-container"]'
            el = await article.query_selector(selector)
            if el:
                text = await el.inner_text()
                # Handle "10K" format
                text = text.replace(",", "")
                if "K" in text:
                    return int(float(text.replace("K", "")) * 1000)
                elif "M" in text:
                    return int(float(text.replace("M", "")) * 1_000_000)
                return int(text) if text.isdigit() else 0
        except:
            pass
        return 0

    def _extract_award_amount(self, text: str) -> Optional[float]:
        """Extract dollar award amounts from text."""
        patterns = [
            r"\$(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)",  # $1,000 or $1000
            r"(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)\s*(?:USD|dollars|bounty)",
            r"(?:award|bounty|paid|payout)\s*(?:of|:)?\s*\$?(\d{1,3}(?:,\d{3})*)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                amount = match.group(1).replace(",", "")
                try:
                    return float(amount)
                except ValueError:
                    continue
        return None

    def _score_tweet(self, item: dict) -> float:
        """Compute confidence score 0.0–1.0."""
        score = 0.30  # base

        # +0.15 per CVE
        score += min(len(item.get("cve_ids", [])) * 0.15, 0.30)

        # +0.20 if award amount mentioned
        if item.get("award_amount") is not None:
            score += 0.20
            # Bonus for large awards
            if item["award_amount"] >= self.config.award_threshold_immediate:
                score += 0.10

        # +0.10 per writeup link
        writeup_keywords = ["writeup", "blog", "medium.com", "github.io"]
        links = " ".join(item.get("links", [])).lower()
        for kw in writeup_keywords:
            if kw in links:
                score += 0.10
                break

        # +0.05 per PoC link
        poc_keywords = ["poc", "exploit", "github.com"]
        for kw in poc_keywords:
            if kw in links:
                score += 0.05
                break

        # +0.10 for reputable author
        if item.get("author_handle", "").lower() in [a.lower() for a in self.config.reputable_authors]:
            score += 0.10

        # +0.05 per media
        if item.get("has_image") or item.get("has_video"):
            score += 0.05

        # +0.05 per 100 likes (capped at +0.15)
        likes = item.get("like_count", 0)
        score += min(likes / 100 * 0.05, 0.15)

        # +0.05 if "critical" or "high" severity mentioned
        severity_keywords = ["critical", "high severity", "CVSS"]
        text_lower = item.get("text", "").lower()
        for kw in severity_keywords:
            if kw in text_lower:
                score += 0.05
                break

        return min(round(score, 2), 1.0)

    async def search(self, query: str = "") -> List[dict]:
        """Public method: search X.com and return scored items."""
        search_query = query or self._build_search_query()
        tweets_raw = await self._search_browser(search_query)

        results = []
        for t in tweets_raw:
            t["confidence_score"] = self._score_tweet(t)
            t["source_query"] = query or "scheduled_search"
            results.append(t)

        results.sort(key=lambda x: x["confidence_score"], reverse=True)
        log.info(f"Found {len(results)} new tweets (max score: {results[0]['confidence_score'] if results else 0})")
        return results

    async def _search_browser(self, search_query: str) -> List[dict]:
        """Scrape X.com using Playwright (browser automation)."""
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-blink-features=AutomationControlled",
                    ],
                )
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 1024},
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/125.0.0.0 Safari/537.36"
                    ),
                )

                if self.config.x_auth_token and self.config.x_csrf_token:
                    await context.add_cookies([
                        {"name": "auth_token", "value": self.config.x_auth_token, "domain": ".x.com", "path": "/"},
                        {"name": "ct0", "value": self.config.x_csrf_token, "domain": ".x.com", "path": "/"},
                    ])

                page = await context.new_page()
                tweets_raw = await self._navigate_and_extract(page, search_query)
                await browser.close()
                return tweets_raw
        except Exception as e:
            log.warning(f"Browser scraping failed: {e}")
            return []


# ─── SQLite Storage ────────────────────────────────────────────────────

class SQLiteStore:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS tweets (
                tweet_id TEXT PRIMARY KEY,
                author_handle TEXT NOT NULL,
                author_display_name TEXT,
                text TEXT,
                timestamp TEXT,
                hashtags TEXT,          -- JSON array
                links TEXT,            -- JSON array
                media_urls TEXT,       -- JSON array
                has_image INTEGER DEFAULT 0,
                has_video INTEGER DEFAULT 0,
                like_count INTEGER DEFAULT 0,
                retweet_count INTEGER DEFAULT 0,
                reply_count INTEGER DEFAULT 0,
                is_thread INTEGER DEFAULT 0,
                thread_id TEXT,
                cve_ids TEXT,          -- JSON array
                award_amount REAL,
                confidence_score REAL DEFAULT 0,
                source_query TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_tweets_hashtags ON tweets(hashtags);
            CREATE INDEX IF NOT EXISTS idx_tweets_cve ON tweets(cve_ids);
            CREATE INDEX IF NOT EXISTS idx_tweets_award ON tweets(award_amount);
            CREATE INDEX IF NOT EXISTS idx_tweets_score ON tweets(confidence_score);
            CREATE INDEX IF NOT EXISTS idx_tweets_author ON tweets(author_handle);
            CREATE INDEX IF NOT EXISTS idx_tweets_timestamp ON tweets(timestamp);

            CREATE TABLE IF NOT EXISTS authors (
                handle TEXT PRIMARY KEY,
                display_name TEXT,
                follower_count INTEGER DEFAULT 0,
                is_verified INTEGER DEFAULT 0,
                last_seen TEXT,
                tweet_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS cvEs (
                cve_id TEXT PRIMARY KEY,
                tweet_id TEXT,
                severity TEXT,
                cvss_score REAL,
                description TEXT,
                first_seen TEXT,
                FOREIGN KEY (tweet_id) REFERENCES tweets(tweet_id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tweet_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,  -- 'immediate', 'daily_digest', 'weekly_report'
                channel TEXT NOT NULL,     -- 'slack', 'telegram', 'email', 'webhook'
                sent_at TEXT,
                delivery_status TEXT DEFAULT 'pending',
                FOREIGN KEY (tweet_id) REFERENCES tweets(tweet_id)
            );

            CREATE TABLE IF NOT EXISTS digests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                digest_type TEXT NOT NULL,  -- 'daily', 'weekly'
                generated_at TEXT,
                content TEXT,               -- JSON
                delivered INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS user_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tweet_id TEXT NOT NULL,
                feedback TEXT NOT NULL,     -- 'useful', 'not_useful'
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (tweet_id) REFERENCES tweets(tweet_id)
            );

            CREATE TABLE IF NOT EXISTS cache (
                cache_key TEXT PRIMARY KEY,
                data TEXT,
                expires_at TEXT
            );
        """)
        self.conn.commit()

    def execute(self, sql: str, params=()) -> list:
        cursor = self.conn.execute(sql, params)
        return cursor.fetchall()

    def insert_tweet(self, item: dict) -> bool:
        """Returns True if inserted, False if duplicate."""
        try:
            self.conn.execute("""
                INSERT OR IGNORE INTO tweets (
                    tweet_id, author_handle, author_display_name, text,
                    timestamp, hashtags, links, media_urls,
                    has_image, has_video, like_count, retweet_count,
                    reply_count, is_thread, thread_id, cve_ids,
                    award_amount, confidence_score, source_query
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                item["tweet_id"],
                item["author_handle"],
                item.get("author_display_name", ""),
                item.get("text", ""),
                item.get("timestamp", ""),
                json.dumps(item.get("hashtags", [])),
                json.dumps(item.get("links", [])),
                json.dumps(item.get("media_urls", [])),
                1 if item.get("has_image") else 0,
                1 if item.get("has_video") else 0,
                item.get("like_count", 0),
                item.get("retweet_count", 0),
                item.get("reply_count", 0),
                1 if item.get("is_thread") else 0,
                item.get("thread_id"),
                json.dumps(item.get("cve_ids", [])),
                item.get("award_amount"),
                item.get("confidence_score", 0.0),
                item.get("source_query", ""),
            ))
            self.conn.commit()
            return self.conn.total_changes > 0
        except sqlite3.IntegrityError:
            return False

    def insert_tweets_batch(self, items: List[dict]) -> int:
        count = 0
        for item in items:
            if self.insert_tweet(item):
                count += 1
        db_name = getattr(self.conn, "database", self.conn.__db_path if hasattr(self.conn, "__db_path") else "sentinel.db")
        log.info(f"Inserted {count}/{len(items)} new tweets")
        return count

    def get_high_severity(self, min_score: float = 0.80, since_hours: int = 24) -> list:
        return self.execute("""
            SELECT * FROM tweets
            WHERE confidence_score >= ? AND timestamp >= datetime('now', ?)
            ORDER BY confidence_score DESC
        """, (min_score, f"-{since_hours} hours"))

    def get_unread_tweets(self, since_hours: int = 24) -> list:
        return self.execute("""
            SELECT * FROM tweets
            WHERE timestamp >= datetime('now', ?)
            ORDER BY confidence_score DESC
        """, (f"-{since_hours} hours"))

    def get_stats(self) -> dict:
        row = self.execute("""
            SELECT
                COUNT(*) as total,
                AVG(confidence_score) as avg_score,
                MAX(award_amount) as max_award,
                COUNT(CASE WHEN award_amount IS NOT NULL THEN 1 END) as with_award,
                COUNT(CASE WHEN cve_ids != '[]' THEN 1 END) as with_cve,
                COUNT(DISTINCT author_handle) as unique_authors
            FROM tweets
        """)[0]
        return dict(row)

    def close(self):
        self.conn.close()


# ─── Main Entry Point ──────────────────────────────────────────────────

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="X.com Scraper")
    parser.add_argument("--hashtags", nargs="+", help="Hashtags to search (space separated)")
    parser.add_argument("--keywords", nargs="+", help="Keywords to search")
    parser.add_argument("--search-interval-mins", type=int, default=60)
    parser.add_argument("--max-tweets", type=int, default=50)
    parser.add_argument("--db-path", default="sentinel.db")
    parser.add_argument("--on-demand", action="store_true", help="Run a single search and print results")
    parser.add_argument("--query", default="", help="Custom search query for on-demand")
    parser.add_argument("--auth-token", help="X.com auth_token cookie")
    parser.add_argument("--csrf-token", help="X.com ct0 cookie")
    parser.add_argument("--daemon", action="store_true", help="Run continuously as a daemon")
    args = parser.parse_args()

    config = ScraperConfig(
        db_path=args.db_path,
        search_interval_mins=args.search_interval_mins,
        max_tweets_per_search=args.max_tweets,
        x_auth_token=args.auth_token,
        x_csrf_token=args.csrf_token,
    )
    if args.hashtags:
        config.hashtags = args.hashtags
    if args.keywords:
        config.keywords = args.keywords

    scraper = XScraper(config)

    if args.on_demand:
        results = await scraper.search(query=args.query)
        print(json.dumps(results, indent=2, default=str))
        return

    if args.daemon:
        log.info(f"Starting daemon — polling every {config.search_interval_mins} minutes")
        while True:
            results = await scraper.search()
            scraper.db.insert_tweets_batch(results)
            # Check for immediate alerts
            for r in results:
                if r["confidence_score"] >= config.score_threshold_immediate or \
                   (r.get("award_amount") or 0) >= config.award_threshold_immediate:
                    log.info(f"HIGH SEVERITY: @{r['author_handle']} — {r['text'][:100]}...")
                    # Dispatch to configured channels (see dispatcher.py)
            log.info(f"Sleeping for {config.search_interval_mins} minutes...")
            await asyncio.sleep(config.search_interval_mins * 60)
    else:
        results = await scraper.search()
        scraper.db.insert_tweets_batch(results)
        stats = scraper.db.get_stats()
        print(f"Stats: {json.dumps(stats, indent=2)}")
        print(json.dumps(results[:5], indent=2, default=str))  # Top 5

    scraper.db.close()


if __name__ == "__main__":
    asyncio.run(main())
