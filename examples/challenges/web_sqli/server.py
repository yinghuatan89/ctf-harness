"""Bundled vulnerable web service for tests/demos (authorized CTF training only).

Deliberately vulnerable: login built via SQL string concatenation (sqlite3).
Routes:
    GET  /              login form
    POST /login         vulnerable authentication (SQLi bypass works)
    GET  /noform        static decoy page (no form - recipes should miss it)
    GET  /hidden_flag   returns the supervisor-demo flag
    POST /check         flag verifier/scorer: {"correct": true/false}
    GET  /robots.txt    decoy robots

Usage: python server.py [port]   (default: picks a free port, prints PORT=)
"""

from __future__ import annotations

import json
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

FLAG_SQLI = "flag{sql_injection_bypass_pwned}"
FLAG_SUPERVISOR = "flag{supervisor_hidden_route_win}"
CORRECT_FLAGS = {FLAG_SQLI, FLAG_SUPERVISOR}

INDEX_HTML = """<!doctype html>
<html><head><title>UltraSecure Login</title></head>
<body>
<h1>UltraSecure(TM) Customer Portal</h1>
<form action="/login" method="post">
  <input name="username" placeholder="username">
  <input name="password" placeholder="password" type="password">
  <input name="submit" type="submit" value="Login">
</form>
<!-- TODO: remove dev backup before deploy -->
</body></html>"""

NOFORM_HTML = "<html><body>nothing to see here.</body></html>"


def check_login(username: str, password: str):
    """Vulnerable on purpose: string-concatenated SQL (SQL training target)."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users (username, password) VALUES ('ctf', 'pass123')")
    conn.commit()
    query = ("SELECT * FROM users WHERE username='" + username +
             "' AND password='" + password + "'")
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    return row


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):  # silence request logging
        pass

    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8"):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, INDEX_HTML)
        elif path == "/noform":
            self._send(200, NOFORM_HTML)
        elif path == "/hidden_flag":
            self._send(200, f"internal debug page\n{FLAG_SUPERVISOR}\n")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\n")
        else:
            self._send(404, "not found")

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        if path == "/login":
            fields = parse_qs(body, keep_blank_values=True)
            username = (fields.get("username") or [""])[0]
            password = (fields.get("password") or [""])[0]
            if check_login(username, password):
                self._send(200, f"<h1>Welcome back!</h1><p>Here is your flag: {FLAG_SQLI}</p>")
            else:
                self._send(200, "<h1>Login failed</h1>")
        elif path == "/check":
            try:
                data = json.loads(body or "{}")
                flag = str(data.get("flag", ""))
            except json.JSONDecodeError:
                self._send(400, '{"correct": false, "message": "bad json"}',
                           "application/json")
                return
            correct = flag.strip() in CORRECT_FLAGS
            self._send(200, json.dumps({"correct": correct,
                                        "message": "correct" if correct else "wrong flag"}),
                       "application/json")
        else:
            self._send(404, "not found")


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    print(f"PORT={server.server_address[1]}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
