"""Session log: append-only JSONL replay of everything that happened."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class SessionLog:
    def __init__(self, path: Path, meta: dict | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        if meta:
            self.log("meta", {"meta": meta})

    def log(self, type_: str, data: dict, lane: str = "main") -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "lane": lane,
            "type": type_,
        }
        record.update(data or {})
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    @staticmethod
    def load(path: Path) -> list[dict]:
        records: list[dict] = []
        try:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError:
            pass
        return records
