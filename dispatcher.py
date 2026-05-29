"""
Dispatch Engine — send alerts and digests via Slack, Telegram, Email, or Webhook.

Usage:
    from dispatcher import Dispatcher
    d = Dispatcher()
    d.send_alert(tweet, channel="slack")
    d.send_daily_digest(channel="telegram")
"""

import asyncio
import json
import logging
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("bountyradar.dispatcher")


@dataclass
class DispatcherConfig:
    # Slack
    slack_webhook_url: Optional[str] = None
    slack_channel: str = "#bug-bounty-alerts"

    # Telegram
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    # Email (SMTP)
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_pass: Optional[str] = None
    email_from: Optional[str] = None
    email_to: Optional[str] = None

    # Generic Webhook
    webhook_url: Optional[str] = None
    webhook_headers: Dict[str, str] = field(default_factory=lambda: {
        "Content-Type": "application/json"
    })

    # Custom Webhook (user-defined)
    custom_webhooks: List[Dict[str, Any]] = field(default_factory=list)


class Dispatcher:
    def __init__(self, config: Optional[DispatcherConfig] = None):
        self.config = config or DispatcherConfig()
        self.http = httpx.AsyncClient(timeout=30.0)

    # ─── Public API ─────────────────────────────────────────────────

    async def send_alert(
        self,
        tweet: Dict[str, Any],
        channels: Optional[List[str]] = None,
    ) -> Dict[str, bool]:
        """
        Send an immediate alert for a high-severity tweet.

        Args:
            tweet: Tweet dict (from scraper or DB)
            channels: ['slack', 'telegram', 'email', 'webhook'] — defaults to all configured

        Returns: {channel_name: success_bool, ...}
        """
        channels = channels or self._detect_configured_channels()
        results = {}

        for ch in channels:
            try:
                if ch == "slack":
                    results[ch] = await self._send_slack_alert(tweet)
                elif ch == "telegram":
                    results[ch] = await self._send_telegram_alert(tweet)
                elif ch == "email":
                    results[ch] = self._send_email_alert(tweet)
                elif ch == "webhook":
                    results[ch] = await self._send_webhook_alert(tweet)
                else:
                    log.warning(f"Unknown channel: {ch}")
                    results[ch] = False
            except Exception as e:
                log.error(f"Failed to send via {ch}: {e}")
                results[ch] = False

        return results

    async def send_daily_digest(
        self,
        tweets: List[Dict[str, Any]],
        channels: Optional[List[str]] = None,
    ) -> Dict[str, bool]:
        """Send a formatted daily digest."""
        channels = channels or self._detect_configured_channels()
        digest = self._build_digest(tweets)
        results = {}

        for ch in channels:
            try:
                if ch == "slack":
                    results[ch] = await self._send_slack_digest(digest)
                elif ch == "telegram":
                    results[ch] = await self._send_telegram_digest(digest)
                elif ch == "email":
                    results[ch] = self._send_email_digest(digest)
                elif ch == "webhook":
                    results[ch] = await self._send_webhook_digest(digest)
            except Exception as e:
                log.error(f"Failed to send digest via {ch}: {e}")
                results[ch] = False

        return results

    async def send_weekly_report(
        self,
        stats: Dict[str, Any],
        channels: Optional[List[str]] = None,
    ) -> Dict[str, bool]:
        """Send weekly analytics and false-positive report."""
        channels = channels or self._detect_configured_channels()
        report = self._build_weekly_report(stats)
        results = {}

        for ch in channels:
            try:
                if ch == "slack":
                    results[ch] = await self._send_slack_blocks(report)
                elif ch == "telegram":
                    results[ch] = await self._send_telegram_message(json.dumps(report, indent=2))
                else:
                    results[ch] = False
            except Exception as e:
                log.error(f"Failed weekly report via {ch}: {e}")
                results[ch] = False

        return results

    # ─── Slack ──────────────────────────────────────────────────────

    async def _send_slack_alert(self, tweet: Dict[str, Any]) -> bool:
        if not self.config.slack_webhook_url:
            return False

        blocks = self._format_slack_alert(tweet)
        resp = await self.http.post(
            self.config.slack_webhook_url,
            json={"channel": self.config.slack_channel, "blocks": blocks},
        )
        return resp.is_success

    async def _send_slack_digest(self, digest: Dict) -> bool:
        if not self.config.slack_webhook_url:
            return False

        blocks = self._format_slack_digest(digest)
        resp = await self.http.post(
            self.config.slack_webhook_url,
            json={"channel": self.config.slack_channel, "blocks": blocks},
        )
        return resp.is_success

    def _format_slack_alert(self, tweet: Dict) -> List[Dict]:
        """Build Slack Block Kit for an immediate alert."""
        handle = tweet.get("author_handle", "unknown")
        text = tweet.get("text", "")[:300]
        score = tweet.get("confidence_score", 0.0)
        award = tweet.get("award_amount")
        cves = tweet.get("cve_ids", [])
        link = f"https://x.com/{handle}/status/{tweet.get('tweet_id', '')}"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 BountyRadar Alert — Score: {score}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Author:* @{handle}"},
                    {"type": "mrkdwn", "text": f"*Score:* {score}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"```{text}```"},
            },
        ]

        if award:
            blocks.append({
                "type": "section",
                "fields": [{"type": "mrkdwn", "text": f"*Award:* ${award:,.2f}"}],
            })
        if cves:
            cve_str = ", ".join(cves)
            blocks.append({
                "type": "section",
                "fields": [{"type": "mrkdwn", "text": f"*CVEs:* {cve_str}"}],
            })

        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Tweet"},
                    "url": link,
                    "action_id": "view_tweet",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "👍 Useful"},
                    "action_id": "feedback_useful",
                    "value": tweet.get("tweet_id", ""),
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "👎 Not Useful"},
                    "action_id": "feedback_not_useful",
                    "value": tweet.get("tweet_id", ""),
                },
            ],
        })

        return blocks

    def _format_slack_digest(self, digest: Dict) -> List[Dict]:
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"📊 BountyRadar Daily Digest — {digest['date']}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Top Alerts:* {digest['top_alerts_count']}\n"
                        f"*Writeups:* {digest['writeups_count']}\n"
                        f"*Tips:* {digest['tips_count']}\n"
                        f"*Total Items:* {digest['total']}"
                    ),
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🔥 Trending Hashtags:* {', '.join(digest['trending_hashtags'][:8])}",
                },
            },
        ]

        for item in digest.get("top_items", [])[:5]:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*@{item['author_handle']}* — Score: {item.get('confidence_score', 0)}\n"
                        f"_{item['summary'][:200]}_\n"
                        f"<https://x.com/{item['author_handle']}/status/{item['tweet_id']}|View>"
                    ),
                },
            })

        return blocks

    # ─── Telegram ───────────────────────────────────────────────────

    async def _send_telegram_alert(self, tweet: Dict[str, Any]) -> bool:
        if not self.config.telegram_bot_token or not self.config.telegram_chat_id:
            return False

        msg = self._format_telegram_alert(tweet)
        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        resp = await self.http.post(url, json={
            "chat_id": self.config.telegram_chat_id,
            "text": msg,
            "parse_mode": "Markdown",
            "disable_web_page_preview": False,
        })
        return resp.is_success

    async def _send_telegram_digest(self, digest: Dict) -> bool:
        if not self.config.telegram_bot_token or not self.config.telegram_chat_id:
            return False

        msg = self._format_telegram_digest(digest)
        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        resp = await self.http.post(url, json={
            "chat_id": self.config.telegram_chat_id,
            "text": msg,
            "parse_mode": "Markdown",
        })

        # If too long, split into parts
        if not resp.is_success and "too long" in resp.text.lower():
            parts = self._split_message(msg)
            for part in parts:
                await self.http.post(url, json={
                    "chat_id": self.config.telegram_chat_id,
                    "text": part,
                    "parse_mode": "Markdown",
                })

        return resp.is_success

    async def _send_telegram_message(self, text: str) -> bool:
        if not self.config.telegram_bot_token or not self.config.telegram_chat_id:
            return False

        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        resp = await self.http.post(url, json={
            "chat_id": self.config.telegram_chat_id,
            "text": text[:4000],
            "parse_mode": "Markdown",
        })
        return resp.is_success

    def _format_telegram_alert(self, tweet: Dict) -> str:
        handle = tweet.get("author_handle", "unknown")
        text = tweet.get("text", "")[:400]
        score = tweet.get("confidence_score", 0.0)
        award = tweet.get("award_amount")
        cves = tweet.get("cve_ids", [])
        link = f"https://x.com/{handle}/status/{tweet.get('tweet_id', '')}"

        parts = [
            f"🚨 *BUG BOUNTY ALERT* (Score: {score})",
            f"👤 *Author:* @{handle}",
            f"📝 `{text}`",
        ]
        if award:
            parts.append(f"💰 *Award:* ${award:,.2f}")
        if cves:
            parts.append(f"🔗 *CVEs:* {', '.join(cves)}")
        parts.append(f"🔗 [View on X]({link})")

        return "\n\n".join(parts)

    def _format_telegram_digest(self, digest: Dict) -> str:
        parts = [
            f"📊 *BountyRadar Daily Digest* — {digest['date']}",
            f"━━━━━━━━━━━━━━━━━",
            f"Total items: {digest['total']}",
            f"Top alerts: {digest['top_alerts_count']}",
            f"Writeups: {digest['writeups_count']}",
            f"Tips: {digest['tips_count']}",
            f"",
            f"🔥 *Trending:* {', '.join(digest['trending_hashtags'][:6])}",
            f"",
        ]

        for item in digest.get("top_items", [])[:5]:
            parts.append(
                f"• @{item['author_handle']} ({item.get('confidence_score', 0)}): "
                f"{item['summary'][:100]}"
            )

        return "\n".join(parts)

    # ─── Email ──────────────────────────────────────────────────────

    def _send_email_alert(self, tweet: Dict[str, Any]) -> bool:
        if not self._email_configured():
            return False

        subject = f"🚨 BB Alert: {tweet.get('author_handle', 'unknown')} — Score {tweet.get('confidence_score', 0)}"
        body = self._format_telegram_alert(tweet)  # Reuse markdown-like format
        return self._send_email(subject, body)

    def _send_email_digest(self, digest: Dict) -> bool:
        if not self._email_configured():
            return False

        subject = f"📊 BountyRadar Daily Digest — {digest['date']}"
        body = self._format_telegram_digest(digest)
        return self._send_email(subject, body)

    def _send_email(self, subject: str, body: str) -> bool:
        try:
            msg = MIMEMultipart()
            msg["From"] = self.config.email_from
            msg["To"] = self.config.email_to
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain", "utf-8"))

            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                server.starttls()
                if self.config.smtp_user and self.config.smtp_pass:
                    server.login(self.config.smtp_user, self.config.smtp_pass)
                server.send_message(msg)

            log.info(f"Email sent: {subject}")
            return True
        except Exception as e:
            log.error(f"Email send failed: {e}")
            return False

    def _email_configured(self) -> bool:
        return all([
            self.config.smtp_host,
            self.config.smtp_user,
            self.config.smtp_pass,
            self.config.email_from,
            self.config.email_to,
        ])

    # ─── Generic Webhook ────────────────────────────────────────────

    async def _send_webhook_alert(self, tweet: Dict[str, Any]) -> bool:
        if not self.config.webhook_url:
            return False

        payload = {
            "type": "alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "tweet_id": tweet.get("tweet_id"),
                "author_handle": tweet.get("author_handle"),
                "text": tweet.get("text", "")[:500],
                "score": tweet.get("confidence_score"),
                "award_amount": tweet.get("award_amount"),
                "cve_ids": tweet.get("cve_ids", []),
                "hashtags": tweet.get("hashtags", []),
                "links": tweet.get("links", []),
                "url": f"https://x.com/{tweet.get('author_handle')}/status/{tweet.get('tweet_id', '')}",
            },
        }

        resp = await self.http.post(
            self.config.webhook_url,
            json=payload,
            headers=self.config.webhook_headers,
        )
        return resp.is_success

    async def _send_webhook_digest(self, digest: Dict) -> bool:
        if not self.config.webhook_url:
            return False

        payload = {
            "type": "daily_digest",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": digest,
        }

        resp = await self.http.post(
            self.config.webhook_url,
            json=payload,
            headers=self.config.webhook_headers,
        )
        return resp.is_success

    # ─── Custom Webhooks (user-defined) ─────────────────────────────

    async def _send_custom_webhooks(self, payload: Dict) -> List[bool]:
        results = []
        for wh in self.config.custom_webhooks:
            url = wh.get("url")
            headers = wh.get("headers", {"Content-Type": "application/json"})
            transform = wh.get("transform", "passthrough")

            if transform == "passthrough":
                data = payload
            elif transform == "slack-format":
                data = {
                    "text": json.dumps(payload.get("data", {}), indent=2),
                }
            else:
                data = payload

            try:
                resp = await self.http.post(url, json=data, headers=headers)
                results.append(resp.is_success)
            except Exception as e:
                log.error(f"Custom webhook {url} failed: {e}")
                results.append(False)

        return results

    # ─── Digest Builder ─────────────────────────────────────────────

    def _build_digest(self, tweets: List[Dict[str, Any]]) -> Dict:
        """Build a structured daily digest from a list of scored tweets."""
        tweets_sorted = sorted(tweets, key=lambda t: t.get("confidence_score", 0), reverse=True)

        top_alerts = [t for t in tweets_sorted if t.get("confidence_score", 0) >= 0.80]
        writeups = [t for t in tweets_sorted if any(
            "writeup" in l.lower() or "blog" in l.lower()
            for l in t.get("links", [])
        )]
        tips = [t for t in tweets_sorted if any(
            "tip" in t.get("text", "").lower() or "trick" in t.get("text", "").lower()
        )]

        # Trending hashtags
        all_hashtags = []
        for t in tweets:
            all_hashtags.extend(t.get("hashtags", []))
        hashtag_counts = Counter(all_hashtags)
        trending = [h for h, c in hashtag_counts.most_common(10)]

        top_items = []
        for t in tweets_sorted[:10]:
            summary = t.get("text", "")[:200].replace("\n", " ")
            top_items.append({
                "tweet_id": t.get("tweet_id"),
                "author_handle": t.get("author_handle"),
                "summary": summary,
                "confidence_score": t.get("confidence_score"),
                "award_amount": t.get("award_amount"),
                "cve_ids": t.get("cve_ids"),
                "hashtags": t.get("hashtags"),
            })

        return {
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "total": len(tweets),
            "top_alerts_count": len(top_alerts),
            "writeups_count": len(writeups),
            "tips_count": len(tips),
            "trending_hashtags": trending,
            "top_items": top_items,
        }

    def _build_weekly_report(self, stats: Dict) -> Dict:
        """Build weekly tuning report."""
        return {
            "type": "weekly_report",
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "stats": stats,
            "suggestions": self._generate_tuning_suggestions(stats),
        }

    def _generate_tuning_suggestions(self, stats: Dict) -> List[str]:
        suggestions = []
        fp_rate = stats.get("false_positive_rate", 0)
        if fp_rate > 0.3:
            suggestions.append("High false-positive rate detected. Consider tightening keyword filters.")
        if stats.get("total", 0) < 10:
            suggestions.append("Low volume detected. Consider broadening hashtag list.")
        if stats.get("with_award", 0) == 0:
            suggestions.append(
                "No award amounts detected. Consider adding '$' and 'payout' as explicit keywords."
            )
        return suggestions

    # ─── Utils ──────────────────────────────────────────────────────

    def _detect_configured_channels(self) -> List[str]:
        channels = []
        if self.config.slack_webhook_url:
            channels.append("slack")
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            channels.append("telegram")
        if self._email_configured():
            channels.append("email")
        if self.config.webhook_url:
            channels.append("webhook")
        return channels or ["slack"]  # default to slack if nothing configured

    def _split_message(self, msg: str, max_len: int = 4000) -> List[str]:
        """Split long messages into chunks at newline boundaries."""
        parts = []
        while len(msg) > max_len:
            split_at = msg.rfind("\n", 0, max_len)
            if split_at == -1:
                split_at = max_len
            parts.append(msg[:split_at])
            msg = msg[split_at:].strip()
        if msg:
            parts.append(msg)
        return parts

    async def close(self):
        await self.http.aclose()
