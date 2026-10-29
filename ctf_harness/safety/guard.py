"""Safety guardrails: workspace jail, shell deny-list, network scope enforcement."""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse


class GuardError(Exception):
    """Raised when an action violates the harness safety policy."""


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]", "ip6-localhost"}

METADATA_HOSTS = {
    "169.254.169.254",       # AWS/GCE/Azure/OpenStack metadata
    "metadata.google.internal",
    "100.100.100.200",       # Alibaba Cloud metadata
    "metadata.oraclecloud.com",
}

# Clearly system-destructive patterns; CTF workspace commands stay allowed.
_SHELL_DENY: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\brm\s+[^;|&]*?\s+/(?:\s|$|\*|--)(?!\S)"), "recursive delete of filesystem root"),
    (re.compile(r"\brm\s+(?:-[a-zA-Z]*[rfR][a-zA-Z]*\s+)+/(?:\s|$|\*)"), "recursive delete of filesystem root"),
    (re.compile(r"\b(?:mkfs(?:\.\w+)?|mke2fs|xfs_repair\s+-L)\b"), "filesystem format/repair"),
    (re.compile(r"\b(?:shutdown|reboot|halt|poweroff)\b"), "power control"),
    (re.compile(r":\s*\(\s*\)\s*\{"), "fork bomb"),
    (re.compile(r"\bdd\b[^|;&]*\bof=/dev/(?!null)"), "raw write to block device"),
    (re.compile(r"\bchmod\s+(?:-[a-zA-Z]*R[a-zA-Z]*\s+)+/(\s|$)"), "recursive chmod on root"),
    (re.compile(r"\bformat\s+[a-z]:", re.IGNORECASE), "windows format command"),
    (re.compile(r"\brd\s+/s", re.IGNORECASE), "windows recursive delete"),
    (re.compile(r"\bdiskpart\b", re.IGNORECASE), "disk partitioning tool"),
    (re.compile(r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200"), "cloud metadata endpoint"),
    (re.compile(r"\bcd\s+C:\\\s*(?:[;|&]|$)", re.IGNORECASE), "leaving workspace to system drive root"),
)


class Guard:
    """Per-challenge guard instance.

    ``scope_hosts`` should contain every host the challenge is allowed to
    touch (parsed from url/remote/scorer/description by
    ``Challenge.scope_hosts``). Loopback is allowed when ``allow_local``
    (default) so local test services work.
    """

    def __init__(self, workspace: Path, *, scope_hosts: set[str] | None = None,
                 allow_local: bool = True):
        self.workspace = Path(workspace).resolve()
        self.scope_hosts = {(h or "").lower().strip("[]") for h in (scope_hosts or set())}
        self.allow_local = allow_local

    # ------------------------------------------------------------------ paths
    def add_scope_host(self, host: str) -> None:
        if host:
            self.scope_hosts.add(host.lower().strip("[]"))

    def check_path(self, target, *, write: bool = False) -> Path:
        """Jail all file operations to the challenge workspace."""
        raw = Path(str(target))
        p = (raw if raw.is_absolute() else self.workspace / raw).resolve()
        norm_ws = os.path.normcase(str(self.workspace))
        norm_p = os.path.normcase(str(p))
        if norm_p != norm_ws and not norm_p.startswith(norm_ws + os.sep):
            raise GuardError(f"path escapes the challenge workspace: {target}")
        return p

    # ------------------------------------------------------------------ shell
    def check_shell(self, cmd: str) -> str:
        if not isinstance(cmd, str) or not cmd.strip():
            raise GuardError("empty shell command")
        for pattern, reason in _SHELL_DENY:
            if pattern.search(cmd):
                raise GuardError(f"command blocked ({reason})")
        return cmd

    # ------------------------------------------------------------------ urls
    def check_url(self, url: str) -> None:
        parsed = urlparse(str(url))
        if parsed.scheme not in ("http", "https"):
            raise GuardError(
                f"scheme '{parsed.scheme or '(none)'}' is not allowed (http/https only): {url}")
        host = (parsed.hostname or "").lower()
        if not host:
            raise GuardError(f"URL has no host: {url}")
        if host in METADATA_HOSTS:
            raise GuardError("cloud metadata endpoints are blocked by the safety guard")
        if self.allow_local and host in LOCAL_HOSTS:
            return
        if host in self.scope_hosts:
            return
        raise GuardError(
            f"host '{host}' is outside the authorized challenge scope "
            f"({', '.join(sorted(self.scope_hosts)) or 'none declared'}). "
            "Declare it with --url/--remote/--allow-host if it is part of the challenge.")
