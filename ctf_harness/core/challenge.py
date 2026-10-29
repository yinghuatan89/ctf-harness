"""Challenge model + recon: everything the solver needs to know up front.

Recon is cheap and local-only: file inventory with magic-byte sniffing,
declared remote/URL endpoints, flag format, platform info and *tool
availability detection* (so the model never wastes steps on tools that are
not installed on this workstation).
"""

from __future__ import annotations

import importlib.util
import platform
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_FLAG_RE = r"(?i)\b(?:flag|ctf|key|secret|sctf|unctf|hgame|d3ctf|ciscn|nepctf)\{[^}\s]{1,128}\}"

MAGIC_TABLE: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "Windows PE"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat / Java class"),
    (b"\xfe\xed\xfa\xce", "Mach-O"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"PK\x03\x04", "ZIP archive (zip/docx/jar/apk)"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ", "xz"),
    (b"7z\xbc\xaf", "7z archive"),
    (b"Rar!", "RAR archive"),
    (b"%PDF", "PDF document"),
    (b"RIFF", "RIFF media (wav/avi/webp)"),
    (b"OggS", "OGG media"),
    (b"fLaC", "FLAC audio"),
    (b"Salted__", "OpenSSL salted ciphertext"),
    (b"-----BEGIN ", "ASCII armor (PEM/PGP key)"),
    (b"SQLite format 3", "SQLite database"),
    (b"<?php", "PHP source"),
    (b"#!", "script with shebang"),
)

EXT_HINTS = {
    ".py": "Python source", ".pyc": "Python bytecode", ".php": "PHP source",
    ".js": "JavaScript", ".ts": "TypeScript", ".html": "HTML", ".css": "CSS",
    ".java": "Java source", ".jar": "Java archive", ".go": "Go source",
    ".rs": "Rust source", ".c": "C source", ".cpp": "C++ source",
    ".h": "C/C++ header", ".s": "Assembly", ".asm": "Assembly",
    ".pcap": "network capture", ".pcapng": "network capture",
    ".png": "PNG image", ".jpg": "JPEG image", ".jpeg": "JPEG image",
    ".gif": "GIF image", ".bmp": "BMP image", ".svg": "SVG image",
    ".zip": "ZIP archive", ".gz": "gzip", ".7z": "7z archive", ".rar": "RAR archive",
    ".tar": "tar archive", ".pem": "PEM key", ".key": "key material",
    ".txt": "text", ".md": "Markdown", ".log": "log file",
    ".sql": "SQL", ".sh": "shell script", ".bat": "Windows batch",
    ".exe": "Windows executable", ".dll": "Windows library",
    ".iso": "disk image", ".img": "disk image", ".vmdk": "VM disk",
    ".wav": "audio", ".mp3": "audio", ".mp4": "video", ".elf": "ELF binary",
}

_EXTERNAL_TOOLS = (
    "gdb", "radare2", "r2", "checksec", "objdump", "strings", "readelf",
    "binwalk", "sqlmap", "nmap", "sage", "steghide", "zsteg", "exiftool",
    "tshark", "hashcat", "john", "upx", "nc", "socat", "curl", "wget",
    "ghidra", "volatility3", "vol.py", "ropper", "ROPgadget", "one_gadget",
)

_PY_MODULES = ("pwn", "z3", "Crypto", "sympy", "numpy", "angr", "PIL", "requests", "capstone")

_AVAIL_CACHE: dict[str, bool] | None = None


def detect_tools(refresh: bool = False) -> dict[str, bool]:
    """Detect which CTF tools are available on this workstation (cached)."""
    global _AVAIL_CACHE
    if _AVAIL_CACHE is None or refresh:
        avail: dict[str, bool] = {}
        for name in _EXTERNAL_TOOLS:
            avail[name] = shutil.which(name) is not None
        for mod in _PY_MODULES:
            try:
                avail["py:" + mod] = importlib.util.find_spec(mod) is not None
            except (ImportError, ValueError):
                avail["py:" + mod] = False
        _AVAIL_CACHE = avail
    return dict(_AVAIL_CACHE)


def _sniff(data: bytes, name: Path) -> str:
    for magic, label in MAGIC_TABLE:
        if data.startswith(magic):
            return label
    ext = name.suffix.lower()
    if ext in EXT_HINTS:
        return EXT_HINTS[ext]
    if data and all(32 <= b < 127 or b in (9, 10, 13) for b in data[:512]):
        return "plain text"
    return "unknown/binary"


def extract_hosts(text: str) -> list[str]:
    """Pull hostnames/URLs out of free text (e.g. a challenge description)."""
    hosts: list[str] = []
    for match in re.finditer(r"https?://([A-Za-z0-9_.\-]+)(?::(\d+))?", text or ""):
        hosts.append(match.group(1).lower())
    for match in re.finditer(r"\b([A-Za-z0-9_.\-]+\.(?:com|net|org|cn|io|cc|top|xyz|edu))\b(?::(\d+))?", text or ""):
        hosts.append(match.group(1).lower())
    seen: set[str] = set()
    out = []
    for host in hosts:
        if host not in seen:
            seen.add(host)
            out.append(host)
    return out


@dataclass
class Challenge:
    """A single CTF challenge to solve."""

    name: str = "challenge"
    category: str | None = None      # web|pwn|crypto|reverse|forensics|misc (None = auto-detect)
    path: Path | None = None         # directory with local challenge files
    url: str | None = None           # web target
    remote: str | None = None        # host:port (pwn)
    flag_format: str = DEFAULT_FLAG_RE
    scorer: str | None = None        # optional URL that verifies a flag (POST {"flag": ...})
    description: str = ""
    files: list[Path] = field(default_factory=list)
    extra_hosts: list[str] = field(default_factory=list)
    challenge_id: int | str | None = None  # CTFd id when synced from a platform

    # ------------------------------------------------------------------ files
    def iter_files(self, max_depth: int = 6, max_files: int = 400):
        """Yield files under ``path`` (sorted, depth- and count-limited)."""
        if not self.path:
            return iter(())
        root = Path(self.path)
        if root.is_file():
            return iter([root])
        out: list[Path] = []
        try:
            for p in sorted(root.rglob("*")):
                if p.is_file():
                    if len(out) >= max_files:
                        break
                    if len(p.relative_to(root).parts) > max_depth:
                        continue
                    if any(part in {".ctfh", ".git", "__pycache__"} for part in p.relative_to(root).parts):
                        continue
                    out.append(p)
        except OSError:
            pass
        return iter(out)

    def _file_lines(self, limit: int = 40) -> list[str]:
        lines = []
        for p in self.iter_files():
            if len(lines) >= limit:
                lines.append(f"  ... ({limit} shown, more may exist)")
                break
            try:
                size = p.stat().st_size
                head = p.read_bytes()[:64]
            except OSError:
                continue
            rel = p.relative_to(self.path) if self.path else p  # type: ignore[arg-type]
            lines.append(f"  {rel}  [{size} bytes, {_sniff(head, p)}]")
        return lines

    # ------------------------------------------------------------------ scope
    def scope_hosts(self) -> set[str]:
        hosts: set[str] = set()
        for host in self.extra_hosts:
            hosts.add(host.lower().strip("[]"))
        for text in (self.url, self.scorer):
            if text:
                match = re.match(r"https?://([^/:]+)", text)
                if match:
                    hosts.add(match.group(1).lower())
        if self.remote:
            host = re.split(r":", self.remote, maxsplit=1)[0]
            if host:
                hosts.add(host.lower())
        for host in extract_hosts(self.description):
            hosts.add(host)
        return hosts

    # ------------------------------------------------------------------ recon
    def recon_summary(self) -> str:
        """Compact recon text injected into the LLM context (pure local)."""
        parts: list[str] = [f"Challenge: {self.name}"]
        parts.append(f"Category: {self.category or 'unknown (auto-detect will apply)'}")
        if self.description:
            desc = " ".join(self.description.split())
            if len(desc) > 600:
                desc = desc[:600] + "..."
            parts.append(f"Description: {desc}")
        if self.path and Path(self.path).exists():
            parts.append("Local files:")
            parts.extend(self._file_lines() or ["  (none)"])
        if self.url:
            parts.append(f"Web target: {self.url}")
        if self.remote:
            parts.append(f"Remote service: {self.remote} (host:port, use pwntools/netcat)")
        if self.scorer:
            parts.append(f"Flag verifier: {self.scorer} (POST JSON {{\"flag\": \"...\"}}; true means accepted)")
        parts.append(f"Flag format (regex): {self.flag_format}")
        parts.append(f"Platform: {platform.system()} (python {sys.version.split()[0]}, cwd = challenge workspace)")
        avail = detect_tools()
        present = sorted(k for k, ok in avail.items() if ok and not k.startswith("py:"))
        present_mods = sorted(k[3:] for k, ok in avail.items() if ok and k.startswith("py:"))
        absent = sorted({"gdb", "radare2", "checksec", "binwalk", "sqlmap", "sage", "steghide",
                          "zsteg", "exiftool", "tshark", "hashcat"} - set(present))
        parts.append(f"Installed CLI tools: {', '.join(present) or 'few'}")
        parts.append(f"Installed python libs: {', '.join(present_mods) or 'few'}")
        if absent:
            parts.append(f"NOT installed (do not use, write pure-python instead): {', '.join(absent)}")
        return "\n".join(parts)
