#!/usr/bin/env python3
"""
Local HTTP Server
Serves index.html + API endpoint (reads SQLite directly).

Usage:  python server.py
Then open http://localhost:8081
"""

import http.server
import json
import sqlite3
import urllib.parse

DB_PATH = "data/sentinel.db"

class SentinelHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api.php" or parsed.path == "/api":
            self.handle_api(parsed.query)
        else:
            super().do_GET()

    def handle_api(self, query_string):
        params = urllib.parse.parse_qs(query_string)
        def g(k, default=None):
            v = params.get(k, [default])
            return v[0] if v else default

        search    = (g("search") or "").strip().lower()
        cve       = (g("cve") or "").strip().lower()
        hashtag   = (g("hashtag") or "").strip().lower()
        author    = (g("author") or "").strip().lower()
        min_score = float(g("min_score", "0"))
        min_award = float(g("min_award", "0"))
        sort      = g("sort", "score")
        limit     = min(int(g("limit", "200")), 200)
        offset    = int(g("offset", "0"))

        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row

            where = []
            params_sql = []

            if search:
                like = f"%{search}%"
                where.append("(LOWER(author_handle) LIKE ? OR LOWER(text) LIKE ? OR LOWER(hashtags) LIKE ? OR LOWER(cve_ids) LIKE ?)")
                params_sql.extend([like]*4)
            if cve:
                where.append("LOWER(cve_ids) LIKE ?")
                params_sql.append(f"%{cve}%")
            if hashtag:
                where.append("LOWER(hashtags) LIKE ?")
                params_sql.append(f"%{hashtag}%")
            if author:
                where.append("LOWER(author_handle) = ?")
                params_sql.append(author)
            if min_score > 0:
                where.append("confidence_score >= ?")
                params_sql.append(min_score)
            if min_award > 0:
                where.append("(award_amount IS NOT NULL AND award_amount >= ?)")
                params_sql.append(min_award)

            w = ("WHERE " + " AND ".join(where)) if where else ""

            order = {"date": "timestamp DESC", "likes": "like_count DESC", "award": "award_amount DESC NULLS LAST"}.get(sort, "confidence_score DESC")

            # Count
            cur = conn.execute(f"SELECT COUNT(*) FROM tweets {w}", params_sql)
            total = cur.fetchone()[0]

            # Fetch
            cur = conn.execute(f"SELECT * FROM tweets {w} ORDER BY {order} LIMIT ? OFFSET ?", params_sql + [limit, offset])
            tweets = []
            for row in cur.fetchall():
                d = dict(row)
                for f in ("hashtags", "links", "media_urls", "cve_ids"):
                    if isinstance(d.get(f), str):
                        d[f] = json.loads(d[f]) if d[f] else []
                for f in ("has_image", "has_video", "like_count", "retweet_count", "reply_count", "is_thread"):
                    d[f] = int(d[f])
                d["confidence_score"] = float(d["confidence_score"])
                d["award_amount"] = float(d["award_amount"]) if d["award_amount"] is not None else None
                tweets.append(d)

            conn.close()

            response = {"total": total, "returned": len(tweets), "offset": offset, "limit": limit, "tweets": tweets}

        except Exception as e:
            response = {"error": str(e)}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(response, default=str, ensure_ascii=False).encode())

    def log_message(self, format, *args):
        pass  # Clean console

if __name__ == "__main__":
    port = 9876
    server = http.server.HTTPServer(("", port), SentinelHandler)
    print(f"http://localhost:{port}")
    print(f"Press Ctrl+C to stop")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
