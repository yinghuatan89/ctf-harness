"""Abstract chat backend + message/usage types."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class LLMError(Exception):
    """Raised when a backend cannot produce a completion."""


@dataclass
class Message:
    role: str            # system | user | assistant
    content: str


@dataclass
class UsageReport:
    """Rough token accounting (chars/4 heuristic) for budget control."""

    prompt_chars: int = 0
    completion_chars: int = 0
    requests: int = 0
    failures: int = 0
    started: float = field(default_factory=time.monotonic)

    @property
    def prompt_tokens(self) -> int:
        return self.prompt_chars // 4

    @property
    def completion_tokens(self) -> int:
        return self.completion_chars // 4

    def add(self, prompt_chars: int, completion_chars: int) -> None:
        self.prompt_chars += max(0, prompt_chars)
        self.completion_chars += max(0, completion_chars)
        self.requests += 1

    def failed(self) -> None:
        self.failures += 1

    def as_dict(self) -> dict:
        return {
            "requests": self.requests, "failures": self.failures,
            "prompt_tokens_est": self.prompt_tokens,
            "completion_tokens_est": self.completion_tokens,
            "wall_s": round(time.monotonic() - self.started, 2),
        }


class ChatBackend(ABC):
    """A minimal chat interface any provider must implement."""

    name = "abstract"

    def __init__(self, *, model: str, timeout: float = 120.0, options: dict | None = None):
        self.model = str(model)
        self.timeout = float(timeout)
        self.options = dict(options or {})

    @abstractmethod
    def chat(self, messages: list[Message], *, max_tokens: int = 4096,
             temperature: float = 0.2, stop: list[str] | None = None) -> str:
        """Return the assistant message content as plain text."""

    # ------------------------------------------------------------------ utils
    def ping(self, *, max_tokens: int = 16) -> tuple[bool, float, str]:
        """Latency probe; returns (ok, ms, error_text)."""
        t0 = time.perf_counter()
        try:
            self.chat([Message("user", "Reply with exactly: pong")],
                      max_tokens=max_tokens, temperature=0.0)
            return True, (time.perf_counter() - t0) * 1000.0, ""
        except Exception as exc:  # noqa: BLE001 - ping must never raise
            return False, (time.perf_counter() - t0) * 1000.0, str(exc)[:200]

    def describe(self) -> str:
        return f"{self.name}:{self.model}"
