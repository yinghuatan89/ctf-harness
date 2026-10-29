"""Category registry: metadata override, alias normalization, auto-detect."""

from __future__ import annotations

from .base import Playbook
from .crypto import CryptoPlaybook
from .forensics import ForensicsPlaybook
from .misc import MiscPlaybook
from .pwn import PwnPlaybook
from .reverse import ReversePlaybook
from .web import WebPlaybook

_ALIASES = {
    "rev": "reverse", "reversing": "reverse", "re": "reverse",
    "bin": "pwn", "binary": "pwn", "binary_exploitation": "pwn",
    "exploit": "pwn", "websec": "web", "web_security": "web",
    "cryptography": "crypto", "cryptology": "crypto", "forensic": "forensics",
    "取证": "forensics", "杂项": "misc", "密码": "crypto", "逆向": "reverse",
    "逆向工程": "reverse", "二进制": "pwn", "网络": "web",
}

PLAYBOOKS: dict[str, Playbook] = {
    "web": WebPlaybook(),
    "pwn": PwnPlaybook(),
    "crypto": CryptoPlaybook(),
    "reverse": ReversePlaybook(),
    "forensics": ForensicsPlaybook(),
    "misc": MiscPlaybook(),
}


def normalize_category(category: str | None) -> str | None:
    if not category:
        return None
    text = str(category).strip().lower().replace(" ", "_")
    text = _ALIASES.get(text, text)
    return text if text in PLAYBOOKS else None


def select(challenge) -> Playbook:
    """Pick the playbook: explicit category first, then auto-detection."""
    canonical = normalize_category(challenge.category)
    if canonical:
        return PLAYBOOKS[canonical]
    best_playbook, best_score = PLAYBOOKS["misc"], 0.0
    for playbook in PLAYBOOKS.values():
        try:
            score = float(playbook.matches(challenge))
        except Exception:  # noqa: BLE001 - detection must never crash
            continue
        if score > best_score:
            best_playbook, best_score = playbook, score
    return best_playbook


__all__ = ["Playbook", "PLAYBOOKS", "normalize_category", "select"]
