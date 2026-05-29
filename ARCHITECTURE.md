# BountyRadar

```
┌─────────────────────────────────────────────────────────────┐
│                        Scheduler                             │
│  cron (daily digest) + event-driven (high-severity alerts)  │
└──────────┬──────────────────────────────────────┬───────────┘
           │ trigger                               │ trigger
           ▼                                       ▼
┌─────────────────────┐              ┌─────────────────────────┐
│  X.com Scraper       │              │  On-Demand Query API    │
│  (Playwright)        │              │  FastAPI / Flask        │
│  - auth cookie reuse │              │  - historical lookup    │
│  - tweet extraction  │              │  - search by hashtag    │
│  - thread parsing    │              │  - filter by CVE/handle │
│  - media link grab   │              └──────────┬──────────────┘
└──────────┬───────────┘                         │
           │ raw items                           │ raw items
           ▼                                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    Ingestion Pipeline                         │
│  1. Deduplication (tweet_id unique index)                    │
│  2. Normalization (trim text, extract metadata)              │
│  3. Enrichment (resolve CVE details, fetch author stats)     │
│  4. Ranking & Scoring (see scoring module)                   │
└──────────────────────────┬──────────────────────────────────┘
                           │ scored items
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Storage Layer                              │
│  SQLite (dev) / Postgres (prod)                              │
│  Tables: tweets, authors, cvEs, media, alerts, digests       │
│  Indexes: (hashtag, cve, award_amount, confidence_score)     │
│  Cache: Redis TTL=15min for repeated queries                 │
└──────────────────────────┬──────────────────────────────────┘
                           │ scored + stored items
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Dispatch Engine                            │
│  - High-severity (score > 0.8 OR award > $X): IMMEDIATE     │
│  - Daily digest: scheduled batch                             │
│  - Weekly tuning report: false positives + suggestions       │
│  Channels: Slack, Telegram, Email, Webhook                   │
└──────────────────────────┬──────────────────────────────────┘
                           │ formatted messages
                           ▼
              ┌────────────────────────────┐
              │  User (Slack/TG/Email/etc) │
              └────────────────────────────┘
```

## Data Flow (per item)

```
Tweet HTML → Playwright → JSON(raw)
  → Dedup check (tweet_id in DB?) → skip if exists
  → Normalize & extract:
      - text, handle, timestamp
      - hashtags, links, media URLs
      - dollar amounts ($1,000 → 1000)
      - CVE pattern matching (CVE-\d{4}-\d{4,})
  → Score (0.0–1.0):
      base: 0.3
      +0.15 per CVE
      +0.20 per award mention
      +0.10 per writeup link
      +0.05 per PoC link
      +0.10 per reputable author (configurable list)
      +0.05 per image/video
      +0.05 per 100 likes (capped at +0.15)
  → Dispatch:
      if score >= 0.80 OR award_amount >= user_threshold:
          IMMEDIATE ALERT
      else:
          buffer for daily digest
  → Insert into DB, update cache, increment Prometheus counter
```
