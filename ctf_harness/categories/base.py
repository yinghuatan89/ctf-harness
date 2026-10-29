"""Playbook base class + shared detection helpers."""

from __future__ import annotations

from pathlib import Path


def _file_heads(challenge, limit: int = 25):
    out = []
    for path in list(challenge.iter_files())[:limit]:
        try:
            out.append((path, path.read_bytes()[:64]))
        except OSError:
            continue
    return out


def _has_ext(challenge, exts: tuple[str, ...]) -> bool:
    return any(path.suffix.lower() in exts
               for path in list(challenge.iter_files())[:80])


def _desc_has(challenge, *words: str) -> bool:
    text = (challenge.description or "").lower()
    return any(word in text for word in words)


class Playbook:
    """A category strategy: detection confidence + prompt + seed hypotheses."""

    id = "misc"
    title = "Generic"

    def matches(self, challenge) -> float:  # noqa: ARG002
        return 0.0

    def system_prompt(self, challenge) -> str:  # noqa: ARG002
        return ""

    def seed_hypotheses(self, challenge) -> list[str]:  # noqa: ARG002
        return []
