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
    since_days: int = 1
    since_date: str = ""
    until_date: str = ""

    # Auth
    x_auth_token: Optional[str] = None  # X.com auth_token cookie
    x_csrf_token: Optional[str] = None  # ct0 cookie
    x_kdt: Optional[str] = None
    x_auth_multi: Optional[str] = None  # auth_multi cookie

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
    GRAPHQL_API = "https://api.x.com/graphql"
    SEARCH_TIMELINE_QUERY = "-TFXKoMnMTKdEXcCn-eahw"
    BEARER_TOKEN = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"

    SEARCH_FEATURES = {
        "rweb_video_screen_enabled": False,
        "rweb_cashtags_enabled": False,
        "profile_label_improvements_pcf_label_in_post_enabled": False,
        "responsive_web_profile_redirect_enabled": False,
        "rweb_tipjar_consumption_enabled": True,
        "verified_phone_label_enabled": False,
        "creator_subscriptions_tweet_preview_api_enabled": True,
        "responsive_web_graphql_timeline_navigation_enabled": True,
        "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
        "premium_content_api_read_enabled": False,
        "communities_web_enable_tweet_community_results_fetch": True,
        "c9s_tweet_anatomy_moderator_badge_enabled": True,
        "responsive_web_grok_analyze_button_fetch_trends_enabled": False,
        "responsive_web_grok_analyze_post_followups_enabled": False,
        "rweb_cashtags_composer_attachment_enabled": False,
        "responsive_web_jetfuel_frame": False,
        "responsive_web_grok_share_attachment_enabled": False,
        "responsive_web_grok_annotations_enabled": False,
        "articles_preview_enabled": True,
        "responsive_web_edit_tweet_api_enabled": True,
        "rweb_conversational_replies_downvote_enabled": False,
        "graphql_is_translatable_rweb_tweet_is_translatable_enabled": True,
        "view_counts_everywhere_api_enabled": True,
        "longform_notetweets_consumption_enabled": True,
        "responsive_web_twitter_article_tweet_consumption_enabled": False,
        "content_disclosure_indicator_enabled": False,
        "content_disclosure_ai_generated_indicator_enabled": False,
        "responsive_web_grok_show_grok_translated_post": False,
        "responsive_web_grok_analysis_button_from_backend": False,
        "post_ctas_fetch_enabled": False,
        "freedom_of_speech_not_reach_fetch_enabled": True,
        "standardized_nudges_misinfo": True,
        "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": True,
        "longform_notetweets_rich_text_read_enabled": False,
        "longform_notetweets_inline_media_enabled": False,
        "responsive_web_grok_image_annotation_enabled": False,
        "responsive_web_grok_imagine_annotation_enabled": False,
        "responsive_web_grok_community_note_auto_translation_is_enabled": False,
        "responsive_web_enhance_cards_enabled": False,
    }

    SEARCH_FIELD_TOGGLES = {
        "withPayments": True,
        "withAuxiliaryUserLabels": True,
        "withArticleRichContentState": False,
        "withArticlePlainText": False,
        "withArticleSummaryText": False,
        "withArticleVoiceOver": False,
        "withGrokAnalyze": False,
        "withDisallowedReplyControls": False,
    }

    def __init__(self, config: ScraperConfig):
        self.config = config
        self.db = SQLiteStore(config.db_path)
        self.seen_ids: set = set()
        self._load_seen_ids()

    def _load_seen_ids(self):
        rows = self.db.execute("SELECT tweet_id FROM tweets")
        self.seen_ids = {r[0] for r in rows}

    def _build_search_query(self) -> str:
        clauses = []
        for ht in self.config.hashtags:
            clauses.append(f"#{ht}")
        for kw in self.config.keywords:
            clauses.append(f'"{kw}"')

        if self.config.since_date and self.config.until_date:
            date_filter = f"since:{self.config.since_date} until:{self.config.until_date}"
        elif self.config.since_date:
            date_filter = f"since:{self.config.since_date}"
        else:
            since = (datetime.now(timezone.utc) - timedelta(days=self.config.since_days)).strftime('%Y-%m-%d')
            date_filter = f"since:{since}"

        exclude = "-filter:retweets -filter:replies lang:en"
        query = " OR ".join(clauses) if clauses else ""
        full_query = f"({query}) {date_filter} {exclude}" if query else f"{date_filter} {exclude}"

        # GraphQL SearchTimeline has 512 char limit on rawQuery
        MAX_QUERY_LEN = 505
        if len(full_query) > MAX_QUERY_LEN:
            while " OR " in query and len(f"({query}) {date_filter} {exclude}") > MAX_QUERY_LEN:
                parts = query.split(" OR ")
                parts.pop()
                query = " OR ".join(parts)
            full_query = f"({query}) {date_filter} {exclude}" if query else f"{date_filter} {exclude}"

        return full_query

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
        tweets_raw = await self._search_graphql(search_query)

        results = []
        for t in tweets_raw:
            t["confidence_score"] = self._score_tweet(t)
            t["source_query"] = query or "scheduled_search"
            results.append(t)

        results.sort(key=lambda x: x["confidence_score"], reverse=True)
        log.info(f"Found {len(results)} new tweets (max score: {results[0]['confidence_score'] if results else 0})")
        return results

    async def _search_graphql(self, search_query: str) -> List[dict]:
        """Call X.com GraphQL SearchTimeline API directly."""
        header_cookies = {}
        if self.config.x_auth_token:
            header_cookies["auth_token"] = self.config.x_auth_token
        if self.config.x_csrf_token:
            header_cookies["ct0"] = self.config.x_csrf_token
        if self.config.x_kdt:
            header_cookies["kdt"] = self.config.x_kdt
        if self.config.x_auth_multi:
            header_cookies["auth_multi"] = self.config.x_auth_multi.replace('"', '')
        header_cookies["twid"] = "u%3D1164212928913932288"

        cookie_str = "; ".join(f"{k}={v}" for k, v in header_cookies.items())

        product_map = {"top": "Top", "latest": "Latest", "people": "People"}
        product = product_map.get(self.config.search_mode, "Top")

        variables = {
            "rawQuery": search_query,
            "count": self.config.max_tweets_per_search,
            "cursor": None,
            "product": product,
            "querySource": "typed_query",
        }

        payload = {
            "variables": json.dumps(variables),
            "features": json.dumps(self.SEARCH_FEATURES),
            "fieldToggles": json.dumps(self.SEARCH_FIELD_TOGGLES),
        }

        url = f"{self.GRAPHQL_API}/{self.SEARCH_TIMELINE_QUERY}/SearchTimeline"
        headers = {
            "authorization": f"Bearer {self.BEARER_TOKEN}",
            "x-csrf-token": self.config.x_csrf_token or "",
            "content-type": "application/json",
            "cookie": cookie_str,
            "origin": "https://x.com",
            "referer": "https://x.com/search",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, json=payload, headers=headers)
                log.info(f"GraphQL API: {resp.status_code} ({len(resp.content)} bytes)")

                if resp.status_code != 200:
                    log.warning(f"API error: {resp.text[:300]}")
                    return []

                data = resp.json()
                return self._parse_search_results(data)

        except Exception as e:
            log.warning(f"GraphQL API call failed: {e}")
            return []

    def _parse_search_results(self, data: dict) -> List[dict]:
        """Parse tweets from SearchTimeline GraphQL response."""
        tweets = []

        try:
            instructions = data["data"]["search_by_raw_query"]["search_timeline"]["timeline"]["instructions"]
        except (KeyError, TypeError):
            return []

        entries = []
        for instr in instructions:
            if instr.get("type") == "TimelineAddEntries":
                entries = instr.get("entries", [])
                break

        for entry in entries:
            content = entry.get("content", {})
            item_content = content.get("itemContent", {})
            tweet_result = item_content.get("tweet_results", {})
            result = tweet_result.get("result", {})
            legacy = result.get("legacy", {})

            if not legacy.get("id_str"):
                continue

            tweet_id = legacy["id_str"]
            if tweet_id in self.seen_ids:
                continue

            # User info from core.user_results.result.core
            core = result.get("core", {})
            user_results = core.get("user_results", {})
            user_result = user_results.get("result", {})
            user_core = user_result.get("core", {})
            screen_name = user_core.get("screen_name", "")
            display_name = user_core.get("name", "")
            try:
                timestamp = datetime.strptime(legacy.get("created_at", ""), "%a %b %d %H:%M:%S %z %Y")
            except:
                timestamp = datetime.now(timezone.utc)

            text = legacy.get("full_text", "")
            entities = legacy.get("entities", {})
            hashtags = [h.get("text", "") for h in entities.get("hashtags", [])]
            urls = [u.get("expanded_url", "") for u in entities.get("urls", [])]
            media = [m.get("media_url_https", "") for m in (entities.get("media", []) if "media" in entities else [])]

            extended_entities = legacy.get("extended_entities", {})
            if extended_entities.get("media"):
                media = [m.get("media_url_https", "") for m in extended_entities["media"]]

            tweet = {
                "tweet_id": tweet_id,
                "author_handle": screen_name,
                "author_display_name": display_name,
                "text": text[:500],
                "timestamp": timestamp.isoformat(),
                "hashtags": list(set(hashtags)),
                "links": list(set(urls)),
                "media_urls": media,
                "has_image": len(media) > 0,
                "has_video": bool(legacy.get("extended_entities", {}).get("media", [{}])[0].get("video_info")),
                "like_count": legacy.get("favorite_count", 0),
                "retweet_count": legacy.get("retweet_count", 0),
                "reply_count": legacy.get("reply_count", 0),
                "is_thread": False,
                "thread_id": None,
                "cve_ids": re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE),
                "award_amount": self._extract_award_amount(text),
                "source_query": "",
            }
            tweets.append(tweet)
            self.seen_ids.add(tweet_id)

        return tweets[: self.config.max_tweets_per_search]


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
