"""Minimal CTFd API v1 client (stdlib only).

Used by ``ctfh rush`` to sync a whole scoreboard: list challenges, download
files, and (opt-in, ``--submit``) auto-submit flags. Works with token auth
or a raw session cookie.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class CTFdError(Exception):
    """Raised when the CTFd API cannot be reached or rejects a call."""


class CTFdClient:
    def __init__(self, base_url: str, *, token: str | None = None,
                 cookie: str | None = None, timeout: float = 20.0):
        if not base_url:
            raise CTFdError("CTFd base URL is required")
        self.base = base_url.rstrip("/")
        if not self.base.startswith(("http://", "https://")):
            raise CTFdError(f"CTFd base URL must start with http(s):// : {base_url}")
        self.token = token
        self.cookie = cookie
        self.timeout = timeout

    # ---------------------------------------------------------------- helpers
    def _headers(self, json_body: bool = False) -> dict:
        headers = {"User-Agent": "ctf-harness/0.1", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Token {self.token}"
        if self.cookie:
            headers["Cookie"] = self.cookie
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    def _request(self, path_or_url: str, *, payload: dict | None = None,
                 binary: bool = False):
        url = path_or_url if path_or_url.startswith("http") \
            else self.base + "/" + path_or_url.lstrip("/")
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            url, data=data,
            headers=self._headers(json_body=payload is not None),
            method="POST" if payload is not None else "GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                raw = resp.read()
                if binary:
                    return resp.headers, raw
                return resp.headers, json.loads(raw.decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:200]
            except Exception:  # noqa: BLE001
                pass
            raise CTFdError(
                f"CTFd HTTP {exc.code} on {url} "
                f"{'(auth problem - check token/cookie) ' if exc.code in (401, 403) else ''}"
                f"{detail}") from exc
        except urllib.error.URLError as exc:
            raise CTFdError(f"cannot reach CTFd at {url}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise CTFdError(f"CTFd returned non-JSON from {url}: {exc}") from exc

    # ------------------------------------------------------------------- API
    def list_challenges(self) -> list[dict]:
        _, data = self._request("/api/v1/challenges")
        items = (data or {}).get("data") or []
        if not isinstance(items, list):
            raise CTFdError("unexpected /api/v1/challenges response shape")
        return items

    def get_challenge(self, challenge_id) -> dict:
        _, data = self._request(f"/api/v1/challenges/{challenge_id}")
        return (data or {}).get("data") or {}

    def download_file(self, file_url: str, dest: Path) -> Path:
        headers, raw = self._request(file_url, binary=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        name = None
        disposition = headers.get("Content-Disposition") or ""
        match = re.search(r'filename="?([^";]+)"?', disposition)
        if match:
            name = match.group(1)
        if not name:
            name = Path(urllib.parse.urlparse(file_url).path).name or "file.bin"
        target = dest.parent / re.sub(r"[^0-9A-Za-z._-]+", "_", name)
        target.write_bytes(raw)
        return target

    def submit_flag(self, challenge_id, flag: str) -> dict:
        _, data = self._request("/api/v1/submissions", payload={
            "challenge_id": challenge_id, "submission": flag})
        inner = (data or {}).get("data") or {}
        if isinstance(inner, str):
            inner = {"status": inner, "message": inner}
        status = str(inner.get("status", "")).lower()
        return {
            "correct": status == "correct",
            "status": status or "unknown",
            "message": str(inner.get("message", ""))[:200],
        }
