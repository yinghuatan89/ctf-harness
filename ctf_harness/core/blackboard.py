"""Blackboard: thread-safe list of persistent facts shared across steps."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class Note:
    ts: float
    tag: str
    text: str


class Blackboard:
    def __init__(self) -> None:
        self._notes: list[Note] = []
        self._lock = threading.Lock()

    def add(self, text: str, tag: str = "note") -> None:
        if not text:
            return
        with self._lock:
            self._notes.append(Note(time.time(), tag[:24], str(text)[:2000]))

    def extend(self, notes: list[Note]) -> None:
        with self._lock:
            self._notes.extend(notes)

    def items(self) -> list[Note]:
        with self._lock:
            return list(self._notes)

    def render(self, limit: int = 60) -> str:
        with self._lock:
            notes = self._notes[-limit:]
        if not notes:
            return ""
        return "\n".join(f"- [{n.tag}] {n.text}" for n in notes)
