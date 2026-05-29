# syntax=docker/dockerfile:1
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Bug Bounty Sentinel"
LABEL org.opencontainers.image.description="Autonomous X.com bug bounty monitoring agent"
LABEL org.opencontainers.image.version="1.0.0"

# ─── System dependencies ──────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ─── Install Playwright browsers ──────────────────────────────────────
RUN pip install --no-cache-dir playwright==1.48.0
RUN playwright install chromium
RUN playwright install-deps

# ─── Create app user ───────────────────────────────────────────────────
RUN groupadd -r sentinel && useradd -r -g sentinel -m -d /app sentinel

# ─── Copy application ─────────────────────────────────────────────────
WORKDIR /app
COPY --chown=sentinel:sentinel . .

RUN pip install --no-cache-dir -r requirements.txt

# ─── Data volume ──────────────────────────────────────────────────────
RUN mkdir -p /app/data && chown sentinel:sentinel /app/data
VOLUME /app/data

# ─── Expose API port ──────────────────────────────────────────────────
EXPOSE 8080

USER sentinel

# ─── Health check ─────────────────────────────────────────────────────
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD curl -s http://localhost:8080/health || exit 1

# ─── Default command (overridable) ────────────────────────────────────
ENTRYPOINT ["python", "cli.py"]
CMD ["run"]
