"""OpenAI-compatible chat backend (stdlib-only HTTP).

Covers, with one implementation:
* cloud vendors: OpenAI, DeepSeek, Moonshot/Kimi, Qwen/DashScope
  (compatible mode), Zhipu GLM, MiniMax, xAI, together.ai, SiliconFlow, ...
* local servers: Ollama (http://localhost:11434/v1), llama.cpp server,
  vLLM, LM Studio, FastChat, any OpenAI-style endpoint.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from ..base import ChatBackend, LLMError, Message

_RETRY_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


class OpenAICompatibleBackend(ChatBackend):
    name = "openai_compatible"

    def __init__(self, *, model: str, base_url: str, api_key: str = "",
                 timeout: float = 120.0, options: dict | None = None,
                 max_retries: int = 2, backoff_s: float = 1.5, **_ignored):
        super().__init__(model=model, timeout=timeout, options=options)
        if not base_url:
            raise LLMError("openai_compatible provider needs a base_url")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or ""
        self.max_retries = int(max_retries)
        self.backoff_s = float(backoff_s)

    # ------------------------------------------------------------------ chat
    def chat(self, messages: list[Message], *, max_tokens: int = 4096,
             temperature: float = 0.2, stop: list[str] | None = None) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": float(temperature),
            "max_tokens": int(max_tokens),
            "stream": False,
        }
        if stop:
            payload["stop"] = stop
        payload.update(self.options.get("extra_body") or {})
        body = json.dumps(payload).encode("utf-8")

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        for key, value in (self.options.get("extra_headers") or {}).items():
            headers[str(key)] = str(value)

        url = self.base_url + "/chat/completions"
        last_error = ""
        for attempt in range(self.max_retries + 1):
            request = urllib.request.Request(url, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                choice = (data.get("choices") or [{}])[0]
                message = choice.get("message") or {}
                content = message.get("content")
                if content is None:
                    # Reasoning models (e.g. deepseek-r1 style) may put the
                    # answer into reasoning_content when content is empty.
                    content = message.get("reasoning_content") or ""
                if not str(content).strip() and data.get("error"):
                    raise LLMError(str(data["error"])[:300])
                return str(content)
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
            except (KeyError, IndexError, json.JSONDecodeError) as exc:
                raise LLMError(f"[{self.describe()}] malformed API response: {exc}") from exc
        raise LLMError(f"[{self.describe()}] {last_error}")
