"""
FastAPI API Server.

Provides:
  - GET  /health          Health check
  - GET  /stats           Database statistics
  - GET  /tweets          Filtered tweet list (by hashtag, CVE, score, handle)
  - POST /search          On-demand search
  - POST /feedback        Record user feedback
  - GET  /alerts          Alert history
  - GET  /config          Current configuration (sanitized)
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Query
from pydantic import BaseModel

from scraper import ScraperConfig, XScraper, SQLiteStore
from scoring import TweetScorer
from dispatcher import Dispatcher, DispatcherConfig

log = logging.getLogger("bountyradar.api")


# ─── Pydantic Models ────────────────────────────────────────────────────

class SearchRequest(BaseModel):
    query: str = ""
    limit: int = 10
    hashtags: list[str] = []
    keywords: list[str] = []

class FeedbackRequest(BaseModel):
    tweet_id: str
    useful: bool

class ConfigResponse(BaseModel):
    hashtags: list[str]
    keywords: list[str]
    interval_minutes: int
    channels: list[str]
    scoring_weights: dict
    alert_thresholds: dict


# ─── App Factory ────────────────────────────────────────────────────────

def create_app(yaml_cfg: dict, api_key: str = ""):
    app = FastAPI(
        title="BountyRadar API",
        version="1.0.0",
        description="Autonomous X.com bug bounty monitoring agent",
    )

    # Initialize services
    scraper_config = _make_scraper_config(yaml_cfg)
    store = SQLiteStore(scraper_config.db_path)
    scorer = TweetScorer()
    dispatcher = Dispatcher(_make_dispatcher_config(yaml_cfg))

    # ─── Auth Middleware ────────────────────────────────────────────

    @app.middleware("http")
    async def auth_middleware(request, call_next):
        if api_key:
            req_key = request.headers.get("X-API-Key", "")
            if req_key != api_key:
                raise HTTPException(status_code=403, detail="Invalid API key")
        return await call_next(request)

    # ─── Routes ─────────────────────────────────────────────────────

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tweet_count": store.get_stats().get("total", 0),
        }

    @app.get("/stats")
    async def stats():
        return store.get_stats()

    @app.get("/tweets")
    async def get_tweets(
        hashtag: Optional[str] = Query(None, description="Filter by hashtag"),
        cve: Optional[str] = Query(None, description="Filter by CVE ID"),
        min_score: float = Query(0.0, ge=0.0, le=1.0),
        handle: Optional[str] = Query(None, description="Filter by author handle"),
        min_award: float = Query(0.0),
        limit: int = Query(50, le=200),
        offset: int = Query(0, ge=0),
    ):
        conditions = ["confidence_score >= ?"]
        params = [min_score]

        if cve:
            conditions.append("cve_ids LIKE ?")
            params.append(f"%{cve}%")
        if handle:
            conditions.append("author_handle = ?")
            params.append(handle.lower())
        if min_award > 0:
            conditions.append("(award_amount IS NOT NULL AND award_amount >= ?)")
            params.append(min_award)

        where = " AND ".join(conditions)
        rows = store.execute(
            f"SELECT * FROM tweets WHERE {where} ORDER BY confidence_score DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        return [dict(r) for r in rows]

    @app.get("/tweets/{tweet_id}")
    async def get_tweet(tweet_id: str):
        rows = store.execute("SELECT * FROM tweets WHERE tweet_id = ?", (tweet_id,))
        if not rows:
            raise HTTPException(status_code=404, detail="Tweet not found")
        return dict(rows[0])

    @app.post("/search")
    async def search(request: SearchRequest):
        """On-demand search."""
        query = request.query or " OR ".join(
            [f"#{h}" for h in request.hashtags or scraper_config.hashtags]
        )
        scraper = XScraper(scraper_config)
        results = asyncio_run(scraper.search(query=query))
        new_count = store.insert_tweets_batch(results)

        for r in results:
            r["confidence_score"] = scorer.score(r)

        return {
            "found": len(results),
            "new": new_count,
            "results": results[: request.limit],
        }

    @app.post("/feedback")
    async def submit_feedback(request: FeedbackRequest):
        store.execute(
            "INSERT INTO user_feedback (tweet_id, feedback) VALUES (?, ?)",
            (request.tweet_id, "useful" if request.useful else "not_useful"),
        )
        store.conn.commit()

        # Feedback-based weight tuning
        feedback_rows = store.execute(
            "SELECT t.*, f.feedback FROM tweets t JOIN user_feedback f ON t.tweet_id = f.tweet_id"
        )
        feedback_data = []
        for row in feedback_rows:
            d = dict(row)
            d["useful"] = d.pop("feedback") == "useful"
            feedback_data.append(d)

        if len(feedback_data) >= 10:
            new_weights = scorer.compute_optimal_weights(feedback_data)
            log.info(f"Tuned scoring weights: {new_weights}")

        return {"status": "recorded", "total_feedback": len(feedback_data)}

    @app.get("/alerts")
    async def get_alerts(limit: int = 20):
        rows = store.execute(
            "SELECT * FROM alerts ORDER BY sent_at DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in rows]

    @app.get("/config")
    async def get_config():
        channels = Dispatcher(_make_dispatcher_config(yaml_cfg))._detect_configured_channels()
        return ConfigResponse(
            hashtags=scraper_config.hashtags,
            keywords=scraper_config.keywords,
            interval_minutes=scraper_config.search_interval_mins,
            channels=channels,
            scoring_weights={
                "relevance": 0.35,
                "evidence": 0.25,
                "authority": 0.20,
                "freshness": 0.10,
                "richness": 0.10,
            },
            alert_thresholds={
                "immediate_score": scraper_config.score_threshold_immediate,
                "immediate_award": scraper_config.award_threshold_immediate,
            },
        )

    return app


# ─── Helpers ────────────────────────────────────────────────────────────

def _make_scraper_config(cfg: dict) -> ScraperConfig:
    s = cfg.get("search", {})
    a = cfg.get("auth", {})
    st = cfg.get("storage", {})
    return ScraperConfig(
        hashtags=s.get("hashtags", ["bugbounty", "CVE", "vulnerability"]),
        keywords=s.get("keywords", ["bounty", "payout", "writeup", "CVE"]),
        db_path=st.get("sqlite_path", "sentinel.db"),
        x_auth_token=a.get("auth_token", "") or os.environ.get("X_AUTH_TOKEN", ""),
        x_csrf_token=a.get("ct0", "") or os.environ.get("X_CT0", ""),
    )

def _make_dispatcher_config(cfg: dict) -> DispatcherConfig:
    d = cfg.get("delivery", {})
    return DispatcherConfig(
        slack_webhook_url=d.get("slack", {}).get("webhook_url"),
        telegram_bot_token=d.get("telegram", {}).get("bot_token"),
        telegram_chat_id=d.get("telegram", {}).get("chat_id"),
        smtp_host=d.get("email", {}).get("smtp_host", "smtp.gmail.com"),
        smtp_user=d.get("email", {}).get("smtp_user"),
        smtp_pass=d.get("email", {}).get("smtp_pass"),
        email_from=d.get("email", {}).get("from"),
        email_to=d.get("email", {}).get("to"),
        webhook_url=d.get("webhook", {}).get("url"),
    )

def asyncio_run(coro):
    """Run async coroutine from sync context."""
    import asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # Already in event loop
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor() as pool:
        future = pool.submit(asyncio.run, coro)
        return future.result()
