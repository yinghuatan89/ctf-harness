"""Flag candidate extraction from any observation text."""

from __future__ import annotations

import re

DEFAULT_FLAG_RE = r"(?i)\b(?:flag|ctf|key|secret|sctf|unctf|hgame|d3ctf|ciscn|nepctf)\{[^}\s]{1,128}\}"

# Generic pattern: any word{...} token - only used when a scorer can verify.
_GENERIC_RE = re.compile(r"\b[a-z][a-z0-9_]{1,15}\{[!-~]{4,200}\}", re.IGNORECASE)

_CODE_WORDS = {
    "def", "class", "function", "json", "dict", "set", "list", "tuple", "args",
    "kwargs", "if", "for", "while", "url", "http", "https", "data", "tool",
    "tool", "href", "src", "id", "name", "type", "font", "color", "width",
}


def extract_candidates(text: str, flag_re: str = DEFAULT_FLAG_RE) -> list[str]:
    """Ordered, de-duplicated candidates matching the challenge flag format."""
    if not text:
        return []
    try:
        pattern = re.compile(flag_re)
    except re.error:
        pattern = re.compile(DEFAULT_FLAG_RE)
    seen: set[str] = set()
    out: list[str] = []
    for match in pattern.finditer(text):
        cand = match.group(0)
        if cand not in seen:
            seen.add(cand)
            out.append(cand)
    return out


def extract_generic(text: str, limit: int = 20) -> list[str]:
    """Loose fallback candidates (``something{...}`` tokens), name-filtered.

    Only worth calling when a scorer endpoint can verify candidates cheaply.
    """
    seen: set[str] = set()
    out: list[str] = []
    for match in _GENERIC_RE.finditer(text or ""):
        cand = match.group(0)
        name = cand.split("{", 1)[0].lower()
        if name in _CODE_WORDS or " " in cand:
            continue
        if cand not in seen:
            seen.add(cand)
            out.append(cand)
        if len(out) >= limit:
            break
    return out
