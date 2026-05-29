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


# ─── X.com API Client ──────────────────────────────────────────────────

X_BEARER = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs=1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
GUEST_TOKEN_URL = "https://api.twitter.com/1.1/guest/activate.json"
SEARCH_URL = "https://twitter.com/i/api/2/search/adaptive.json"

class XScraper:
    def __init__(self, config: ScraperConfig):
        self.config = config
        self.db = SQLiteStore(config.db_path)
        self.seen_ids: set = set()
        self._load_seen_ids()
        self._client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
        )

    async def _ensure_auth(self):
        """Get a guest token or use auth cookies for API access."""
        if self.config.x_auth_token and self.config.x_csrf_token:
            self._client.headers.update({
                "authorization": f"Bearer {X_BEARER}",
                "x-csrf-token": self.config.x_csrf_token,
                "cookie": f"auth_token={self.config.x_auth_token}; ct0={self.config.x_csrf_token}",
            })
        else:
            resp = await self._client.post(GUEST_TOKEN_URL, headers={"authorization": f"Bearer {X_BEARER}"})
            if resp.status_code == 200:
                gt = resp.json().get("guest_token", "")
                self._client.headers.update({
                    "authorization": f"Bearer {X_BEARER}",
                    "x-guest-token": gt,
                })
            else:
                log.warning(f"Failed to get guest token: {resp.status_code}")
        self._client.headers.update({
            "content-type": "application/json",
            "origin": "https://twitter.com",
            "referer": "https://twitter.com/search",
            "x-twitter-client-language": "en",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })

    def _load_seen_ids(self):
        rows = self.db.execute("SELECT tweet_id FROM tweets")
        self.seen_ids = {r[0] for r in rows}

    def _build_search_query(self, since_days: int = 7) -> str:
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
        return full_query

    def _extract_award_amount(self, text: str) -> Optional[float]:
        patterns = [
            r"\$(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)",
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
        score = 0.30
        score += min(len(item.get("cve_ids", [])) * 0.15, 0.30)
        if item.get("award_amount") is not None:
            score += 0.20
            if item["award_amount"] >= self.config.award_threshold_immediate:
                score += 0.10
        links = " ".join(item.get("links", [])).lower()
        for kw in ["writeup", "blog", "medium.com", "github.io"]:
            if kw in links:
                score += 0.10
                break
        for kw in ["poc", "exploit", "github.com"]:
            if kw in links:
                score += 0.05
                break
        if item.get("author_handle", "").lower() in [a.lower() for a in self.config.reputable_authors]:
            score += 0.10
        if item.get("has_image") or item.get("has_video"):
            score += 0.05
        score += min(item.get("like_count", 0) / 100 * 0.05, 0.15)
        text_lower = item.get("text", "").lower()
        for kw in ["critical", "high severity", "CVSS"]:
            if kw in text_lower:
                score += 0.05
                break
        return min(round(score, 2), 1.0)

    def _parse_adaptive_tweet(self, t: dict, users: dict) -> Optional[dict]:
        try:
            tweet_id = t.get("id_str", "")
            if not tweet_id:
                return None

            created = t.get("created_at", "")
            try:
                ts = datetime.strptime(created, "%a %b %d %H:%M:%S %z %Y")
            except:
                ts = datetime.now(timezone.utc)

            text = t.get("full_text", t.get("text", ""))
            user = users.get(t.get("user_id_str", ""), {})
            entities = t.get("entities", {})
            ext_media = t.get("extended_entities", {}).get("media", []) or entities.get("media", [])

            hashtags = [h["text"] for h in entities.get("hashtags", [])]
            urls = [u["expanded_url"] for u in entities.get("urls", []) if not u.get("display_url", "").startswith("pic.")]
            media_urls = [m["media_url_https"] for m in ext_media]
            has_image = any(m.get("type") == "photo" for m in ext_media)
            has_video = any(m.get("type") in ("video", "animated_gif") for m in ext_media)
            cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)

            return {
                "tweet_id": tweet_id,
                "author_handle": user.get("screen_name", ""),
                "author_display_name": user.get("name", ""),
                "text": text[:500],
                "timestamp": ts.isoformat(),
                "hashtags": list(set(hashtags)),
                "links": list(set(urls)),
                "media_urls": media_urls,
                "has_image": has_image,
                "has_video": has_video,
                "like_count": int(t.get("favorite_count", 0)),
                "retweet_count": int(t.get("retweet_count", 0)),
                "reply_count": int(t.get("reply_count", 0)),
                "is_thread": bool(t.get("self_thread")),
                "thread_id": str(t.get("conversation_id_str", "")),
                "cve_ids": cve_ids,
                "award_amount": self._extract_award_amount(text),
                "source_query": "",
            }
        except Exception as e:
            log.debug(f"Parse error: {e}")
            return None

    async def search(self, query: str = "") -> List[dict]:
        search_query = query or self._build_search_query()
        await self._ensure_auth()
        log.info(f"Searching API: {search_query[:80]}...")
        params = {
            "q": search_query,
            "count": self.config.max_tweets_per_search,
            "pc": 1,
            "spelling_corrections": 1,
            "include_ext_alt_text": "true",
            "include_ext_media_availability": "true",
            "include_ext_media_color": "true",
            "include_ext_media_forward_identifier": "true",
            "include_ext_media_business_labels": "true",
        }
        try:
            resp = await self._client.get(SEARCH_URL, params=params, follow_redirects=True)
            body = resp.text
            log.info(f"API response {resp.status_code} from {resp.url}: {len(body)} bytes")
            if resp.status_code != 200:
                log.warning(f"Body: {body[:300]}")
                return []
            if not body:
                log.warning("Empty response body")
                return []
            data = resp.json()
            global_objects = data.get("globalObjects", {})
            tweets_map = global_objects.get("tweets", {})
            users_map = global_objects.get("users", {})
        except Exception as e:
            log.warning(f"API call failed: {e}")
            return []

        results = []
        for tid, tweet_data in tweets_map.items():
            if tid in self.seen_ids:
                continue
            tweet = self._parse_adaptive_tweet(tweet_data, users_map)
            if tweet:
                tweet["confidence_score"] = self._score_tweet(tweet)
                tweet["source_query"] = query or "scheduled_search"
                results.append(tweet)
                self.seen_ids.add(tid)
        results.sort(key=lambda x: x["confidence_score"], reverse=True)
        log.info(f"Found {len(results)} new tweets (max score: {results[0]['confidence_score'] if results else 0})")
        return results

    def close(self):
        self.db.close()


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
