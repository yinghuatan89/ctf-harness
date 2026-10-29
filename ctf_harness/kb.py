"""Knowledge base: your writeup corpus, injected by relevance.

Drop ``*.md`` / ``*.txt`` files (writeups, cheatsheets, your own playbooks)
into ``./kb`` or ``~/.ctfh/kb``. Before the L2 lanes start, the most
relevant paragraphs (keyword overlap with the challenge recon) are
injected into the system prompt - so the framework gets smarter with every
writeup you collect, without any code changes.

Optional per-file tags line::

    tags: sqli, mysql, auth-bypass

Speed tip: before a competition, drop the writeups of that organiser's past
events into ``kb/`` - the strategist and lanes will lean on them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_WORD_RE = re.compile(r"[a-z0-9_]{4,}")
_STOP = {"this", "that", "with", "from", "your", "have", "will", "which",
         "when", "what", "then", "they", "them", "there", "here", "into",
         "some", "more", "very", "just", "like", "also", "been", "were",
         "should", "could", "would", "challenge", "flag", "ctf", "solve",
         "problem", "solution", "answer"}


def _tokens(text: str) -> set[str]:
    return {t for t in _WORD_RE.findall(text.lower()) if t not in _STOP}


@dataclass
class Paragraph:
    source: str
    text: str
    tokens: frozenset


class KnowledgeBase:
    def __init__(self, paragraphs: list[Paragraph]):
        self.paragraphs = paragraphs

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, dirs: list[Path], *, max_files: int = 300,
             max_chars_per: int = 30_000) -> "KnowledgeBase":
        paragraphs: list[Paragraph] = []
        seen: set[Path] = set()
        for directory in dirs:
            if not directory.is_dir():
                continue
            files = sorted(directory.rglob("*.md")) + sorted(directory.rglob("*.txt"))
            for path in files[:max_files]:
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")[:max_chars_per]
                except OSError:
                    continue
                for chunk in text.split("\n\n"):
                    chunk = chunk.strip()
                    if len(chunk) < 40:
                        continue
                    paragraphs.append(Paragraph(
                        source=path.name, text=chunk, tokens=frozenset(_tokens(chunk))))
        return cls(paragraphs)

    # ---------------------------------------------------------------- search
    def search(self, query: str, *, limit: int = 6, max_chars: int = 3500) -> str:
        if not self.paragraphs:
            return ""
        query_tokens = _tokens(query)
        if not query_tokens:
            return ""
        scored = []
        for paragraph in self.paragraphs:
            overlap = len(paragraph.tokens & query_tokens)
            if overlap >= 2:
                scored.append((overlap, paragraph))
        scored.sort(key=lambda pair: -pair[0])
        chunks: list[str] = []
        total = 0
        for overlap, paragraph in scored[:limit]:
            snippet = paragraph.text[:600]
            chunks.append(f"({paragraph.source}) {snippet}")
            total += len(snippet)
            if total >= max_chars:
                break
        return "\n---\n".join(chunks)

    def stats(self) -> dict:
        return {"paragraphs": len(self.paragraphs),
                "chars": sum(len(p.text) for p in self.paragraphs)}


def default_kb_dirs() -> list[Path]:
    return [Path.cwd() / "kb", Path.home() / ".ctfh" / "kb"]
