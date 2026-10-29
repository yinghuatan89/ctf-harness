"""Anthropic Messages API backend (stdlib-only HTTP)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from ..base import ChatBackend, LLMError, Message

_RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}


class AnthropicBackend(ChatBackend):
    name = "anthropic"
    DEFAULT_BASE = "https://api.anthropic.com"

    def __init__(self, *, model: str, api_key: str, base_url: str | None = None,
                 timeout: float = 120.0, options: dict | None = None,
                 max_retries: int = 2, backoff_s: float = 1.5, **_ignored):
        super().__init__(model=model, timeout=timeout, options=options)
        if not api_key:
            raise LLMError("anthropic provider needs an api_key (or env: reference)")
        self.api_key = api_key
        self.base_url = (base_url or self.DEFAULT_BASE).rstrip("/")
        self.max_retries = int(max_retries)
        self.backoff_s = float(backoff_s)

    def chat(self, messages: list[Message], *, max_tokens: int = 4096,
             temperature: float = 0.2, stop: list[str] | None = None) -> str:
        system = "\n\n".join(m.content for m in messages if m.role == "system").strip()
        rest = [m for m in messages if m.role != "system"]
        # Anthropic requires first message to be from the user and strict alternation.
        if rest and rest[0].role != "user":
            rest.insert(0, Message("user", "Continue solving the challenge."))
        payload: dict = {
            "model": self.model,
            "max_tokens": int(max_tokens),
            "temperature": float(temperature),
            "messages": [{"role": m.role, "content": m.content} for m in rest],
        }
        if system:
            payload["system"] = system
        if stop:
            payload["stop_sequences"] = stop
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        url = self.base_url + "/v1/messages"
        for key, value in (self.options.get("extra_headers") or {}).items():
            headers[str(key)] = str(value)
        last_error = ""
        for attempt in range(self.max_retries + 1):
            request = urllib.request.Request(url, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                chunks = [blk.get("text", "") for blk in data.get("content", [])
                          if isinstance(blk, dict) and blk.get("type") == "text"]
                return "".join(chunks)
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", "replace")[:300]
                except Exception:  # noqa: BLE001
                    pass
                last_error = f"HTTP {exc.code}: {detail}"
                if exc.code in _RETRY_STATUS and attempt < self.max_retries:
                    time.sleep(self.backoff_s * (attempt + 1))
                    continue
                raise LLMError(f"[{self.describe()}] {last_error}") from exc
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last_error = f"connection error: {exc}"
                if attempt < self.max_retries:
                    time.sleep(self.backoff_s * (attempt + 1))
                    continue
                raise LLMError(f"[{self.describe()}] {last_error}") from exc
            except json.JSONDecodeError as exc:
                raise LLMError(f"[{self.describe()}] malformed API response: {exc}") from exc
        raise LLMError(f"[{self.describe()}] {last_error}")
