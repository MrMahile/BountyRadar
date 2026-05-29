# BountyRadar  — Enhanced Monitoring System

> Autonomous X.com scanner for bug bounty payouts, CVEs, writeups and community discussion.  
> Built from the original prompt concept into a working system with code, infrastructure, and ML-based ranking.

---

## What Was Enhanced

| Dimension | Original Prompt | Enhanced System |
|-----------|----------------|-----------------|
| **Architecture** | Conceptual | Full layered architecture (scraper → pipeline → scoring → dispatch) |
| **Scraping** | Pseudocode | Working Playwright scraper with auth, scroll, thread detection |
| **Scoring** | 0–1 heuristic | 5-dimension weighted scoring with ML feedback tuning |
| **Storage** | Mentioned | Full SQLite/Postgres schema with 6 tables + indexes |
| **Delivery** | Email/Slack/Telegram | Slack Block Kit, Telegram Markdown, SMTP, generic webhook, custom webhooks |
| **CLI** | None | `sentinel run/stats/query/digest/feedback/serve` |
| **Config** | None | Full YAML config with 50+ parameters |
| **API** | None | FastAPI server with search, feedback, stats, alerts endpoints |
| **Deployment** | None | Docker + docker-compose, health checks, logging |
| **Feedback Loop** | Mentioned | `feedback` table + automatic weight tuning from user signals |
| **Noise Filtering** | None | Regex-based noise patterns + excluded keywords |
| **Thread Detection** | None | Thread context extraction |
| **CVE Enrichment** | Mentioned | CVE extraction + `cvEs` table |
| **Rate Limiting** | Brief | Exponential backoff, configurable delays, cache |

---

## Quick Start

```bash
# 1. Install
pip install -r requirements.txt
playwright install chromium

# 2. Configure
cp config.yaml sentinel.yaml
# Edit sentinel.yaml — set auth tokens, delivery channels

# 3. Initialize
python cli.py --config sentinel.yaml init

# 4. Run a single search
python cli.py --config sentinel.yaml run --once

# 5. Run as daemon
python cli.py --config sentinel.yaml run

# 6. Or with Docker
docker compose up -d
```

---

## System Modules

```
scraper.py       — Playwright-based X.com scraper + SQLite store (300+ lines)
scoring.py       — 5-dimension ML-enhanced scoring engine (350+ lines)
dispatcher.py    — Multi-channel alert/digest dispatch (400+ lines)
cli.py           — Click-based CLI entry point (350+ lines)
api_server.py    — FastAPI REST API (250+ lines)
config.yaml      — Full YAML configuration (180+ lines)
```

---

## Scoring Dimensions (Weighted)

| Dimension | Weight | Signals |
|-----------|--------|---------|
| **Relevance** | 0.35 | Hashtag match, keyword density, platform mention |
| **Evidence** | 0.25 | CVE presence, award amount, writeup/PoC links, severity mention |
| **Authority** | 0.20 | Author tier (1/2/3), engagement (log scale), thread depth |
| **Freshness** | 0.10 | Exponential decay curve (6h → 72h+) |
| **Richness** | 0.10 | Text length, media, code blocks, link count |

Weights are automatically tunable via user feedback hill-climbing.

---

## CLI Commands

```bash
sentinel run                    # Continuous daemon mode
sentinel run --once             # Single search + print
sentinel run --query "CVE-2026" # Custom query

sentinel digest                 # Send daily digest
sentinel query "$5000 bounty"   # On-demand search
sentinel stats                  # DB statistics
sentinel feedback --tweet-id X --useful
sentinel serve                  # Start API server
sentinel init                   # Initialize DB + config
```

---

## Alert Rules

| Condition | Action |
|-----------|--------|
| Score ≥ 0.80 | Immediate alert (all channels) |
| Award ≥ $1,000 | Immediate alert (all channels) |
| CVE + Award ≥ $500 | Immediate alert (high-confidence channels) |
| Score ≥ 0.30 | Included in daily digest |
| Novel technique | Weekly report highlight |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/stats` | DB statistics |
| GET | `/tweets` | Filtered tweet list (?hashtag=&cve=&min_score=&handle=) |
| GET | `/tweets/{id}` | Single tweet |
| POST | `/search` | On-demand search |
| POST | `/feedback` | Record user feedback |
| GET | `/alerts` | Alert history |
| GET | `/config` | Current configuration |

---

## Deployment

```bash
# Docker (default: scraper daemon + API)
docker compose up -d

# With Redis cache
docker compose --profile cache up -d

# View logs
docker compose logs -f sentinel-daemon

# Scale
docker compose up -d --scale sentinel-daemon=2
```

---

## Monitoring & Metrics

- **Health check** every 60s on `/health`
- **Structured JSON logging** to stdout (Docker driver)
- **Prometheus** metrics ready (extend via FastAPI middleware)
- **Weekly report** with false-positive rate and tuning suggestions
- **Feedback dashboard** via API `/stats` endpoint

---

## Extending

1. **Add a new delivery channel** — subclass or add to `dispatcher.py`
2. **Add a scoring dimension** — add method to `TweetScorer`, update weights
3. **Add a data source** — subclass `XScraper` interface, implement `search()`
4. **Add ML model** — integrate via `scoring.py`'s `score()` plug point

---

## Comparison: Original vs Enhanced

```
Original:  "Build an autonomous X.com monitoring assistant that scans posts..."
Enhanced:  System with working code, database schema, scoring engine,
           multi-channel dispatch, CLI, API, Docker deployment, and
           feedback-driven ML tuning — ready to deploy in 5 minutes.
```

---

## File Index

```
sentinel/
├── ARCHITECTURE.md       # System architecture diagram + data flow
├── ENHANCED_PROMPT.md    # This file — enhancement summary
├── config.yaml           # Full YAML configuration template
├── scraper.py            # Playwright scraper + SQLite storage
├── scoring.py            # 5-dimension scoring engine + feedback tuning
├── dispatcher.py         # Slack/Telegram/Email/Webhook dispatch
├── cli.py                # Click-based CLI entry point
├── api_server.py         # FastAPI REST API
├── Dockerfile            # Container image
├── docker-compose.yml    # Multi-service deployment
├── requirements.txt      # Python dependencies
├── pyproject.toml        # Package metadata
└── data/                 # SQLite database (auto-created)
```
