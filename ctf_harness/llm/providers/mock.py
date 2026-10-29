"""Scripted mock backend for offline tests and demos.

Reads a JSONL file where each line is either a plain string or
``{"content": "..."}``. Every ``chat()`` call returns the next line.
``{NAME}`` tokens inside lines are substituted from the ``vars`` mapping
(simple string replace - JSON braces in the script are untouched).

When the script is exhausted the backend returns a ``declare_stuck`` call
so agent loops terminate deterministically.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from ..base import ChatBackend, Message


class MockBackend(ChatBackend):
    name = "mock"

    def __init__(self, *, model: str = "mock-1", script: str | None = None,
                 lines: list | None = None, vars: dict | None = None,
                 options: dict | None = None, **_ignored):
        super().__init__(model=model, timeout=30.0, options=options)
        self.lines: list[str] = []
        if lines:
            self.lines = [str(x) for x in lines]
        elif script:
            path = Path(script)
            if not path.is_file():
                raise ValueError(f"mock script not found: {script}")
            for raw in path.read_text(encoding="utf-8").splitlines():
                raw = raw.strip()
                if not raw or raw.startswith("#"):
                    continue
                try:
                    obj = json.loads(raw)
                    self.lines.append(str(obj.get("content", "")) if isinstance(obj, dict) else str(obj))
                except json.JSONDecodeError:
                    self.lines.append(raw)
        self.vars = dict(vars or {})
        self._index = 0
        self._lock = threading.Lock()

    def _substitute(self, text: str) -> str:
        for key, value in self.vars.items():
            text = text.replace("{" + str(key) + "}", str(value))
        return text

    def chat(self, messages: list[Message], *, max_tokens: int = 4096,
             temperature: float = 0.2, stop: list[str] | None = None) -> str:
        with self._lock:
            if self._index >= len(self.lines):
                return '```tool\n{"tool": "declare_stuck", "args": {"reason": "mock script exhausted"}}\n```'
            line = self.lines[self._index]
            self._index += 1
            return self._substitute(line)

    # tests may want to inspect progress
    @property
    def consumed(self) -> int:
        with self._lock:
            return self._index
