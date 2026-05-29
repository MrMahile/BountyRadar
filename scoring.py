"""
Scoring Engine — ML-enhanced relevance ranking for bug bounty tweets.

Two modes:
  1. Heuristic scoring (fast, deterministic) — used inline in scraper.py
  2. ML-boosted scoring (optional, lightweight) — uses a small TF-IDF + logistic regression
     trained on user feedback signals.

Usage:
    from scoring import TweetScorer
    scorer = TweetScorer()
    score = scorer.score(tweet_dict)
"""

import json
import logging
import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("bountyradar.scoring")


class TweetScorer:
    """
    Multi-factor scoring engine.

    Scoring dimensions (each 0.0–1.0, weighted):
      - relevance:   0.35  (keyword/hashtag match strength)
      - evidence:    0.25  (CVE, award, links to writeup/PoC)
      - authority:   0.20  (author reputation, engagement)
      - freshness:   0.10  (recency decay)
      - richness:    0.10  (media, thread context, text length)

    Final score = weighted average, clipped to [0, 1].
    """

    # Weight by dimension
    DIM_WEIGHTS = {
        "relevance": 0.35,
        "evidence": 0.25,
        "authority": 0.20,
        "freshness": 0.10,
        "richness": 0.10,
    }

    # Author reputation list (handle → tier: 1=vetted, 2=known, 3=emerging)
    REPUTABLE_AUTHORS = {
        # Platform accounts
        "hackerone": 1,
        "bugcrowd": 1,
        "yeswehack": 1,
        "intigriti": 1,
        "synack": 1,
        # Top researchers
        "sehacure": 1,
        "renaudragen": 1,
        "samwcyo": 1,
        "naglinagli": 1,
        "amonsecurity": 1,
        "bogdantirca": 1,
        "proabiral": 1,
        "darkmatter": 1,
        "albinowax": 1,
        "honoki": 1,
        "stokfredrik": 1,
        "insiderphd": 1,
        "tomnomnom": 1,
        "pdp": 1,
        "garethheyes": 1,
        "joeleonjr": 1,
        "d0nut": 2,
        "rez0": 2,
        "hackerscrolls": 2,
        "bountywriteup": 2,
        "infosecwriteups": 2,
    }

    # CVE severity keywords
    SEVERITY_KEYWORDS = {
        "critical": 1.0,
        "9.9": 1.0,
        "9.8": 1.0,
        "10.0": 1.0,
        "high severity": 0.8,
        "7.": 0.8,      # CVSS 7.x
        "8.": 0.8,
        "medium": 0.5,
        "low": 0.2,
    }

    # Boilerplate / noise keywords that signal low value
    NOISE_PATTERNS = [
        r"follow.*retweet.*win",
        r"RT @",
        r"check.*bio.*link",
        r"dm\s+(?:me\s+)?for\s+",
        r"limited.*spots?",
        r"sign\s*up\s*now",
        r"hire\s+me",
        r"looking\s+for\s+work",
    ]

    # Writeup domains
    WRITEUP_DOMAINS = {
        "medium.com", "github.io", "blog.", "seclists.org",
        "exploit-db.com", "pentester.land", "infosecwriteups.com",
        "bountywriteup.com", "hackerone.com/reports",
        "bugcrowd.com", "yeswehack.com/reports",
    }

    def __init__(self):
        self.noise_re = re.compile(
            "|".join(self.NOISE_PATTERNS), re.IGNORECASE
        )

    def score(
        self,
        tweet: dict,
        user_weights: Optional[Dict[str, float]] = None,
    ) -> float:
        """
        Compute overall score for a tweet dict.

        Accepts both raw scraped dicts and DB row dicts.
        """
        if self._is_noise(tweet):
            return 0.0

        dims = {
            "relevance": self._score_relevance(tweet),
            "evidence": self._score_evidence(tweet),
            "authority": self._score_authority(tweet),
            "freshness": self._score_freshness(tweet),
            "richness": self._score_richness(tweet),
        }

        weights = user_weights or self.DIM_WEIGHTS
        final = sum(dims[k] * weights.get(k, self.DIM_WEIGHTS[k]) for k in dims)
        return round(min(final, 1.0), 4)

    def score_batch(
        self,
        tweets: List[dict],
        user_weights: Optional[Dict[str, float]] = None,
    ) -> List[Tuple[dict, float]]:
        """Score multiple tweets and return sorted (tweet, score) pairs."""
        scored = [(t, self.score(t, user_weights)) for t in tweets]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def explain(self, tweet: dict) -> dict:
        """Return per-dimension breakdown for debugging."""
        return {
            "relevance": round(self._score_relevance(tweet), 4),
            "evidence": round(self._score_evidence(tweet), 4),
            "authority": round(self._score_authority(tweet), 4),
            "freshness": round(self._score_freshness(tweet), 4),
            "richness": round(self._score_richness(tweet), 4),
        }

    # ─── Dimension scorers ─────────────────────────────────────────

    def _is_noise(self, tweet: dict) -> bool:
        text = tweet.get("text", "")
        return bool(self.noise_re.search(text))

    def _score_relevance(self, tweet: dict) -> float:
        """
        How well does the tweet match bug bounty topics?

        Signals:
          - Number of matching hashtags from our primary list
          - Number of matching keywords
          - Presence of bug bounty platform names in text
        """
        text = tweet.get("text", "").lower()
        hashtags = [h.lower() for h in tweet.get("hashtags", [])]

        primary_hashtags = {
            "bugbounty", "vulnerability", "0day", "infosec",
            "securityresearch", "pentest", "exploit", "cve",
            "bugbountytips", "bugbountywriteup", "hackerone",
            "bugcrowd", "zeroday", "responsibledisclosure",
        }

        # Hashtag match ratio
        matched_h = sum(1 for h in hashtags if h in primary_hashtags)
        ht_score = min(matched_h / 3, 1.0)  # 3+ hashtags = full score

        # Keyword density
        keywords = [
            "bounty", "vulnerability", "exploit", "poc", "writeup",
            "cve", "disclosure", "patch", "mitigation", "pwned",
            "bug", "security", "bypass", "rce", "xss", "sqli", "ssrf",
        ]
        words = set(text.split())
        matched_kw = len(words & set(keywords))
        kw_score = min(matched_kw / 4, 1.0)

        # Platform mention
        platforms = ["hackerone", "bugcrowd", "yeswehack", "intigriti", "synack"]
        plat_score = 0.3 if any(p in text for p in platforms) else 0.0

        return min(ht_score * 0.5 + kw_score * 0.35 + plat_score * 0.15, 1.0)

    def _score_evidence(self, tweet: dict) -> float:
        """
        How much supporting evidence does the tweet provide?

        Signals:
          - CVE IDs present
          - Award amount mentioned
          - Link to writeup / report / PoC
          - Has image/video (screenshot of report)
        """
        text = tweet.get("text", "").lower()
        links = tweet.get("links", [])
        cves = tweet.get("cve_ids", [])
        award = tweet.get("award_amount")

        score = 0.0

        # CVE presence
        if cves:
            # Higher score for specific CVE identifiers
            score += min(len(cves) * 0.25, 0.50)

        # Award amount
        if award is not None:
            try:
                amt = float(award)
                score += 0.20
                if amt > 500:
                    score += 0.10
                if amt > 5_000:
                    score += 0.15
                if amt > 50_000:
                    score += 0.25
            except (ValueError, TypeError):
                pass

        # Writeup links
        for link in links:
            domain = urlparse(link).netloc.lower()
            if any(wd in domain for wd in self.WRITEUP_DOMAINS):
                score += 0.20
                break

        # PoC / exploit mentions
        if re.search(r"\bpoc\b", text) or re.search(r"\bexploit\b", text):
            score += 0.10

        # Severity mention
        for kw, val in self.SEVERITY_KEYWORDS.items():
            if kw in text:
                score += 0.10 * val
                break

        # Media (screenshot of report confirmation)
        if tweet.get("has_image") or tweet.get("has_video"):
            score += 0.05

        return min(score, 1.0)

    def _score_authority(self, tweet: dict) -> float:
        """
        How authoritative is the source?

        Signals:
          - Author reputation tier
          - Engagement (likes, retweets)
          - Verified account
          - Is thread (indicates in-depth content)
        """
        handle = tweet.get("author_handle", "").lower()
        tier = self.REPUTABLE_AUTHORS.get(handle, 3)

        # Author reputation
        if tier == 1:
            auth_score = 0.50
        elif tier == 2:
            auth_score = 0.30
        else:
            auth_score = 0.05

        # Engagement (normalized, log scale)
        total_eng = (
            tweet.get("like_count", 0)
            + tweet.get("retweet_count", 0) * 2
            + tweet.get("reply_count", 0) * 0.5
        )
        eng_score = min(math.log10(max(total_eng, 1)) / 5, 0.30)

        # Thread bonus
        thread_bonus = 0.10 if tweet.get("is_thread") else 0.0

        # Platform account bonus
        if handle in {"hackerone", "bugcrowd", "yeswehack", "intigriti"}:
            auth_score = 0.60  # Override: platform announcements are highly authoritative

        return min(auth_score + eng_score + thread_bonus, 1.0)

    def _score_freshness(self, tweet: dict) -> float:
        """
        How recent is the tweet? Decay over time.

        Tweets < 6 hours old  → 1.0
        6–24 hours            → 0.8
        24–48 hours           → 0.5
        48–72 hours           → 0.2
        > 72 hours            → 0.05
        """
        ts_str = tweet.get("timestamp")
        if not ts_str:
            return 0.5

        try:
            if isinstance(ts_str, str):
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                ts = ts_str
            now = datetime.now(timezone.utc)
            delta_hours = (now - ts).total_seconds() / 3600
        except (ValueError, TypeError):
            return 0.5

        if delta_hours < 6:
            return 1.0
        elif delta_hours < 24:
            return 0.8
        elif delta_hours < 48:
            return 0.5
        elif delta_hours < 72:
            return 0.2
        else:
            return 0.05

    def _score_richness(self, tweet: dict) -> float:
        """
        How information-rich is the tweet content?

        Signals:
          - Text length (tweet length correlates with detail)
          - Has media (screenshots)
          - Has links
          - Is part of a thread
          - Has code block or technical indicators
        """
        text = tweet.get("text", "")
        links = tweet.get("links", [])

        score = 0.0

        # Text length: longer = more detailed
        length = len(text)
        if length > 250:
            score += 0.30
        elif length > 150:
            score += 0.20
        elif length > 50:
            score += 0.10

        # Links
        score += min(len(links) * 0.10, 0.30)

        # Media
        if tweet.get("has_image"):
            score += 0.15
        if tweet.get("has_video"):
            score += 0.20

        # Thread
        if tweet.get("is_thread"):
            score += 0.15

        # Technical indicators in text
        if re.search(r"```|`[a-z]+`", text):  # Code blocks
            score += 0.15
        if re.search(r"HTTP|GET|POST|curl|wget|nmap|burp", text, re.I):
            score += 0.10

        return min(score, 1.0)

    # ─── Feedback-based weight tuning ──────────────────────────────

    def compute_optimal_weights(
        self, feedback_data: List[dict]
    ) -> Dict[str, float]:
        """
        Simple hill-climbing approach to tune weights based on user feedback.

        feedback_data: list of {"useful": True/False, **tweet_fields}
        Returns: adjusted DIM_WEIGHTS
        """
        if not feedback_data:
            return self.DIM_WEIGHTS.copy()

        weights = self.DIM_WEIGHTS.copy()
        step = 0.05

        for epoch in range(10):
            best = None
            best_accuracy = 0.0

            for dim in weights:
                for direction in [1, -1]:
                    trial = weights.copy()
                    trial[dim] += step * direction
                    trial[dim] = max(0.05, min(0.60, trial[dim]))

                    # Normalize to sum to 1.0
                    total = sum(trial.values())
                    trial = {k: v / total for k, v in trial.items()}

                    accuracy = self._eval_weights(feedback_data, trial)
                    if accuracy > best_accuracy:
                        best_accuracy = accuracy
                        best = trial

            if best is None or abs(best_accuracy - self._eval_weights(feedback_data, weights)) < 0.001:
                break

            weights = best

        return weights

    def _eval_weights(self, feedback_data: List[dict], weights: dict) -> float:
        correct = 0
        for item in feedback_data:
            predicted = self.score(item, weights)
            actual = 1.0 if item.get("useful") else 0.0
            if abs(predicted - actual) < 0.5:
                correct += 1
        return correct / max(len(feedback_data), 1)


# ─── Helper ────────────────────────────────────────────────────────────

def urlparse(url):
    from urllib.parse import urlparse as _up
    return _up(url)


# ─── CLI Usage ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    scorer = TweetScorer()

    test_tweet = {
        "tweet_id": "12345",
        "author_handle": "sehacure",
        "text": (
            "Just got a $15,000 bounty for a critical RCE in ProductX! "
            "CVE-2026-1234. Full writeup: https://medium.com/... "
            "#bugbounty #CVE #infosec"
        ),
        "hashtags": ["bugbounty", "CVE", "infosec", "rce"],
        "links": ["https://medium.com/..."],
        "media_urls": [],
        "has_image": True,
        "has_video": False,
        "like_count": 342,
        "retweet_count": 89,
        "reply_count": 12,
        "is_thread": False,
        "cve_ids": ["CVE-2026-1234"],
        "award_amount": 15000.0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    score = scorer.score(test_tweet)
    explanation = scorer.explain(test_tweet)
    print(f"Overall score: {score}")
    print(f"Explanation: {json.dumps(explanation, indent=2)}")
