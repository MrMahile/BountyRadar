#!/usr/bin/env python3
"""
CLI entry point.

Usage:
    sentinel run                    Run scraping loop
    sentinel run --once             Single search, print results
    sentinel digest                 Generate and send daily digest
    sentinel query "search string"  On-demand search
    sentinel stats                  Show database stats
    sentinel feedback --tweet <id> --useful/--not-useful
    sentinel serve                  Start the API server

Config:
    sentinel --config /path/to/config.yaml
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import click
import yaml

from scraper import ScraperConfig, XScraper, SQLiteStore
from scoring import TweetScorer
from dispatcher import Dispatcher, DispatcherConfig

log = logging.getLogger("bountyradar.cli")


def load_config(config_path: str) -> dict:
    path = Path(config_path)
    if not path.exists():
        click.echo(f"Config not found: {config_path}", err=True)
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)


def make_scraper_config(cfg: dict) -> ScraperConfig:
    s = cfg.get("search", {})
    a = cfg.get("auth", {})
    st = cfg.get("storage", {})
    adv = cfg.get("advanced", {})
    return ScraperConfig(
        hashtags=s.get("hashtags", []),
        keywords=s.get("keywords", []),
        search_mode=s.get("mode", "top"),
        search_interval_mins=s.get("interval_minutes", 60),
        max_tweets_per_search=s.get("max_per_query", 50),
        since_days=s.get("since_days", 1),
        since_date=s.get("since_date", ""),
        until_date=s.get("until_date", ""),
        x_auth_token=a.get("auth_token", "") or os.environ.get("X_AUTH_TOKEN", ""),
        x_csrf_token=a.get("ct0", "") or os.environ.get("X_CT0", ""),
        x_kdt=a.get("kdt", "") or os.environ.get("X_KDT", ""),
        x_auth_multi=a.get("auth_multi", "") or os.environ.get("X_AUTH_MULTI", ""),
        db_path=st.get("sqlite_path", "bountyradar.db"),
        award_threshold_immediate=cfg.get("alerts", {}).get("immediate", {}).get("min_award", 1000),
        score_threshold_immediate=cfg.get("scoring", {}).get("immediate_alert_score", 0.80),
        reputable_authors=list(cfg.get("scoring", {}).get("reputable_authors", {}).keys()),
    )


def make_dispatcher_config(cfg: dict) -> DispatcherConfig:
    d = cfg.get("delivery", {})
    a_imm = cfg.get("alerts", {}).get("immediate", {})
    return DispatcherConfig(
        slack_webhook_url=d.get("slack", {}).get("webhook_url"),
        slack_channel=d.get("slack", {}).get("channel", "#bug-bounty-alerts"),
        telegram_bot_token=d.get("telegram", {}).get("bot_token"),
        telegram_chat_id=d.get("telegram", {}).get("chat_id"),
        smtp_host=d.get("email", {}).get("smtp_host", "smtp.gmail.com"),
        smtp_port=d.get("email", {}).get("smtp_port", 587),
        smtp_user=d.get("email", {}).get("smtp_user"),
        smtp_pass=d.get("email", {}).get("smtp_pass"),
        email_from=d.get("email", {}).get("from"),
        email_to=d.get("email", {}).get("to"),
        webhook_url=d.get("webhook", {}).get("url"),
        webhook_headers=d.get("webhook", {}).get("headers", {"Content-Type": "application/json"}),
        custom_webhooks=d.get("custom_webhooks", []),
    )


@click.group()
@click.option("--config", "-c", default="config.yaml", help="Config file path")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx, config, verbose):
    """Autonomous X.com monitoring agent."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["verbose"] = verbose

    cfg = load_config(config)
    ctx.obj["cfg"] = cfg

    log_level = logging.DEBUG if verbose else getattr(logging, cfg.get("advanced", {}).get("log_level", "INFO"))
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


@cli.command()
@click.option("--once", is_flag=True, help="Run once and exit")
@click.option("--query", default="", help="Custom search query")
@click.option("--no-send", is_flag=True, help="Don't send alerts, only store")
@click.option("--interval", type=int, default=0, help="Poll interval in minutes (overrides config)")
@click.pass_context
def run(ctx, once, query, no_send, interval):
    """Run the scraper continuously (default) or a single search (--once).

    Without --once, polls X.com every N minutes (configurable in config.yaml).
    New tweets are exported to data/tweets.json for the dashboard automatically.
    """
    cfg = ctx.obj["cfg"]

    scraper_config = make_scraper_config(cfg)
    interval_mins = interval or scraper_config.search_interval_mins
    loop_count = 0

    while True:
        loop_count += 1
        scraper = XScraper(scraper_config)
        scorer = TweetScorer()
        dispatcher = Dispatcher(make_dispatcher_config(cfg))

        async def _run():
            results = await scraper.search(query=query)
            new_count = scraper.db.insert_tweets_batch(results)

            for r in results:
                r["confidence_score"] = scorer.score(r)

            export_tweets_json(scraper.db)

            if once:
                print(json.dumps(results, indent=2, default=str))
                return True  # Signal to exit

            if not no_send:
                for r in results:
                    if r["confidence_score"] >= scraper_config.score_threshold_immediate or \
                       (r.get("award_amount") or 0) >= scraper_config.award_threshold_immediate:
                        click.echo(f"🚨 HIGH: @{r['author_handle']} — {r['text'][:80]}...")
                        await dispatcher.send_alert(r)

            stats = scraper.db.get_stats()
            click.echo(f"[{loop_count}] New: {new_count} | Total: {stats['total']} | Avg: {stats['avg_score']:.2f}")
            return False

        should_exit = asyncio.run(_run())
        scraper.db.close()

        if once or should_exit:
            break

        click.echo(f"Sleeping {interval_mins} min...")
        import time
        time.sleep(interval_mins * 60)


def export_tweets_json(store):
    """Export all tweets from SQLite to data/tweets.json for the dashboard."""
    rows = store.execute("SELECT * FROM tweets ORDER BY timestamp DESC")
    tweets = []
    seen = set()
    for r in rows:
        d = dict(r)
        if d["tweet_id"] not in seen:
            seen.add(d["tweet_id"])
            for f in ("hashtags", "links", "media_urls", "cve_ids"):
                if isinstance(d.get(f), str):
                    d[f] = json.loads(d[f]) if d[f] else []
            d["has_image"] = int(d["has_image"])
            d["has_video"] = int(d["has_video"])
            d["like_count"] = int(d["like_count"])
            d["retweet_count"] = int(d["retweet_count"])
            d["reply_count"] = int(d["reply_count"])
            d["is_thread"] = int(d["is_thread"])
            d["confidence_score"] = float(d["confidence_score"])
            d["award_amount"] = float(d["award_amount"]) if d["award_amount"] is not None else None
            tweets.append(d)
    import os
    os.makedirs("data", exist_ok=True)
    with open("data/tweets.json", "w") as f:
        json.dump(tweets, f, indent=2)
    click.echo(f"Exported {len(tweets)} tweets to data/tweets.json")


@cli.command()
@click.pass_context
def digest(ctx):
    """Generate and send the daily digest."""
    cfg = ctx.obj["cfg"]
    scraper_config = make_scraper_config(cfg)
    scraper = XScraper(scraper_config)
    dispatcher = Dispatcher(make_dispatcher_config(cfg))

    async def _digest():
        tweets_raw = scraper.db.get_unread_tweets(since_hours=24)
        tweet_dicts = [dict(r) for r in tweets_raw]
        click.echo(f"Building digest from {len(tweet_dicts)} items...")
        await dispatcher.send_daily_digest(tweet_dicts)
        click.echo("Digest sent.")

    asyncio.run(_digest())
    scraper.db.close()


@cli.command()
@click.argument("search_query", nargs=-1, required=True)
@click.option("--limit", default=10, help="Max results")
@click.pass_context
def query(ctx, search_query, limit):
    """On-demand search with a custom query."""
    cfg = ctx.obj["cfg"]
    scraper_config = make_scraper_config(cfg)
    scraper = XScraper(scraper_config)
    scorer = TweetScorer()

    q = " ".join(search_query)
    async def _query():
        results = await scraper.search(query=q)
        for r in results[:limit]:
            r["confidence_score"] = scorer.score(r)
            print(f"[{r['confidence_score']:.2f}] @{r['author_handle']}: {r['text'][:120]}")
            if r.get("award_amount"):
                print(f"       💰 ${r['award_amount']:,.2f}")
            if r.get("cve_ids"):
                print(f"       🔗 CVEs: {', '.join(r['cve_ids'])}")
            print()
        print(f"Total found: {len(results)}")

    asyncio.run(_query())
    scraper.db.close()


@cli.command()
@click.pass_context
def stats(ctx):
    """Show database statistics."""
    cfg = ctx.obj["cfg"]
    scraper_config = make_scraper_config(cfg)
    store = SQLiteStore(scraper_config.db_path)

    stats = store.get_stats()
    click.echo("📊 Statistics")
    click.echo("━" * 40)
    click.echo(f"Total tweets:        {stats['total']}")
    click.echo(f"Unique authors:      {stats['unique_authors']}")
    click.echo(f"Avg confidence:      {stats['avg_score']:.3f}")
    click.echo(f"Max award:           ${stats['max_award']:,.2f}" if stats['max_award'] else "Max award:           N/A")
    click.echo(f"With award mention:  {stats['with_award']}")
    click.echo(f"With CVE:            {stats['with_cve']}")

    export_tweets_json(store)
    store.close()


@cli.command()
@click.option("--tweet-id", required=True, help="Tweet ID to provide feedback on")
@click.option("--useful/--not-useful", default=True, help="Was this useful?")
@click.pass_context
def feedback(ctx, tweet_id, useful):
    """Record user feedback for weight tuning."""
    cfg = ctx.obj["cfg"]
    scraper_config = make_scraper_config(cfg)
    store = SQLiteStore(scraper_config.db_path)

    store.execute(
        "INSERT INTO user_feedback (tweet_id, feedback) VALUES (?, ?)",
        (tweet_id, "useful" if useful else "not_useful"),
    )
    store.conn.commit()
    click.echo(f"Feedback recorded: {tweet_id} → {'👍' if useful else '👎'}")
    store.close()


@cli.command()
@click.pass_context
def serve(ctx):
    """Start the API server."""
    cfg = ctx.obj["cfg"]
    api_cfg = cfg.get("api", {})
    if not api_cfg.get("enabled", False):
        click.echo("API server is disabled in config.", err=True)
        sys.exit(1)

    host = api_cfg.get("host", "0.0.0.0")
    port = api_cfg.get("port", 8080)
    api_key = api_cfg.get("api_key", "")

    from api_server import create_app
    app = create_app(cfg, api_key)
    click.echo(f"📡 API server starting on {host}:{port}")
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")


@cli.command()
@click.pass_context
def init(ctx):
    """Initialize the database and config."""
    cfg = ctx.obj["cfg"]
    scraper_config = make_scraper_config(cfg)

    # Ensure data directory
    data_dir = os.path.dirname(scraper_config.db_path)
    if data_dir:
        Path(data_dir).mkdir(parents=True, exist_ok=True)

    # Create DB tables
    store = SQLiteStore(scraper_config.db_path)
    click.echo(f"✅ Database initialized: {scraper_config.db_path}")

    config_path = ctx.obj["config_path"]
    click.echo(f"✅ Config loaded: {config_path}")
    click.echo(f"   Hashtags: {', '.join(scraper_config.hashtags[:5])}...")
    click.echo(f"   Interval: {scraper_config.search_interval_mins} min")
    d = Dispatcher(make_dispatcher_config(cfg))
    click.echo(f"   Channels: {', '.join(d._detect_configured_channels())}")

    store.close()


@cli.command()
@click.pass_context
def export(ctx):
    """Export database to data/tweets.json for the dashboard."""
    cfg = ctx.obj["cfg"]
    scraper_config = make_scraper_config(cfg)
    store = SQLiteStore(scraper_config.db_path)
    export_tweets_json(store)
    store.close()


if __name__ == "__main__":
    cli()
