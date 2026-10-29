"""L0: zero-thought deterministic heuristics (sub-second, zero tokens).

The speed-first first stage of the pipeline. Before any LLM token is spent,
every challenge file is pushed through a cascade of classic decodings:

plain-text regex -> base64/base32 (nested) -> hex -> gzip/zlib/bz2/xz/tar/zip
(incl. tiny password list) -> Caesar shifts -> single-byte XOR ->
known-key XOR.

Only candidates matching the declared flag format survive, so the false
positive rate stays near zero.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import io
import lzma
import re
import tarfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .flagextract import extract_candidates

MAX_DEPTH = 4
_MEMBER_READ_CAP = 1_000_000

_ZIP_PASSWORDS = ("", "password", "ctf", "flag", "123456", "12345678", "admin",
                  "infected", "1234", "qwerty", "password123")


@dataclass
class Finding:
    flag: str
    via: str
    detail: str = ""


def fast_scan(path, flag_re: str, *, budget_s: float = 20.0,
              max_file_bytes: int = 2_000_000, max_files: int = 500) -> list[Finding]:
    """Scan every file under ``path`` through the decoding cascade."""
    findings: list[Finding] = []
    seen: set[str] = set()

    def add(text: str, via: str, detail: str = "") -> None:
        for cand in extract_candidates(text, flag_re):
            if cand not in seen:
                seen.add(cand)
                findings.append(Finding(cand, via, (detail or via)[:200]))

    root = Path(path)
    if root.is_file():
        files = [root]
    elif root.is_dir():
        files = [p for p in sorted(root.rglob("*"))
                 if p.is_file() and not any(part in {".ctfh", "__pycache__"} for part in p.parts)]
    else:
        return findings

    deadline = time.monotonic() + budget_s
    for file in files[:max_files]:
        if time.monotonic() > deadline:
            break
        try:
            data = file.read_bytes()
        except OSError:
            continue
        if not data or b".ctfh" in str(file).encode():
            continue
        if len(data) > max_file_bytes:
            data = data[:max_file_bytes]
        _scan_blob(data, add, deadline, depth=0, origin=file.name)
    return findings


# --------------------------------------------------------------------------- #
def _scan_blob(data: bytes, add, deadline: float, depth: int, origin: str) -> None:
    text = data.decode("latin-1")
    add(text, f"L0:{origin}")

    if depth >= MAX_DEPTH or time.monotonic() > deadline or len(data) > 4_000_000:
        return

    compact = re.sub(r"\s+", "", text)

    # ---- base64 / base32 -------------------------------------------------- #
    if len(compact) >= 8 and len(compact) % 4 == 0 and \
            re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        for decoder, via in (
            (lambda s: base64.b64decode(s + "=" * ((-len(s)) % 4)), "base64"),
            (lambda s: base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4)), "base64url"),
        ):
            try:
                decoded = decoder(compact)
            except (binascii.Error, ValueError):
                continue
            if decoded and b"\x00" not in decoded[:64]:
                add(decoded.decode("latin-1"), f"{via}({origin})")
                _scan_blob(decoded, add, deadline, depth + 1, f"{via}:{origin}")
    if len(compact) >= 16 and len(compact) % 8 == 0 and re.fullmatch(r"[A-Z2-7=]+", compact):
        try:
            decoded = base64.b32decode(compact)
            add(decoded.decode("latin-1"), f"base32({origin})")
            _scan_blob(decoded, add, deadline, depth + 1, f"base32:{origin}")
        except (binascii.Error, ValueError):
            pass

    # ---- hex -------------------------------------------------------------- #
    if len(compact) >= 16 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        try:
            decoded = bytes.fromhex(compact)
            add(decoded.decode("latin-1"), f"hex({origin})")
            _scan_blob(decoded, add, deadline, depth + 1, f"hex:{origin}")
        except ValueError:
            pass

    # ---- compression containers ------------------------------------------- #
    for magic, decompress, via in (
        (b"\x1f\x8b", gzip.decompress, "gzip"),
        (b"BZh", bz2.decompress, "bzip2"),
        (b"\xfd7zXZ", lzma.decompress, "xz"),
    ):
        if data.startswith(magic):
            try:
                decoded = decompress(data)
                add(decoded.decode("latin-1"), f"{via}({origin})")
                _scan_blob(decoded, add, deadline, depth + 1, f"{via}:{origin}")
            except (OSError, EOFError, lzma.LZMAError):
                pass
    try:
        decoded = __import__("zlib").decompress(data)
        add(decoded.decode("latin-1"), f"zlib({origin})")
        _scan_blob(decoded, add, deadline, depth + 1, f"zlib:{origin}")
    except Exception:  # noqa: BLE001 - zlib probe on random data raises often
        pass

    # ---- archive containers ------------------------------------------------ #
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist()[:50]:
                if info.is_dir() or "__MACOSX" in info.filename:
                    continue
                for password in _ZIP_PASSWORDS:
                    try:
                        member = zf.read(info, pwd=password.encode() or None)
                    except (RuntimeError, zipfile.BadZipFile):
                        break  # wrong password / broken archive
                    except Exception:  # noqa: BLE001
                        break
                    if member:
                        via = f"zip:{info.filename}" + (f"(pw={password!r})" if password else "")
                        add(member.decode("latin-1"), f"L0:{via}")
                        _scan_blob(member, add, deadline, depth + 1, via)
                        break
    except (zipfile.BadZipFile, OSError):
        pass
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            for member in tf.getmembers()[:30]:
                if not member.isfile():
                    continue
                handle = tf.extractfile(member)
                if handle is None:
                    continue
                content = handle.read(_MEMBER_READ_CAP)
                add(content.decode("latin-1"), f"L0:tar:{member.name}")
                _scan_blob(content, add, deadline, depth + 1, f"tar:{member.name}")
    except (tarfile.TarError, OSError, EOFError):
        pass

    # ---- classical shifts --------------------------------------------------- #
    if len(data) <= 100_000:
        for shift in range(1, 26):
            shifted = bytes(
                ((c - 65 + shift) % 26) + 65 if 65 <= c <= 90 else
                ((c - 97 + shift) % 26) + 97 if 97 <= c <= 122 else c
                for c in data)
            add(shifted.decode("latin-1"), f"caesar+{shift}({origin})")

    # ---- xor ---------------------------------------------------------------- #
    if len(data) <= 200_000:
        sample = data[:4096]
        for key in range(256):
            if sum(1 for b in sample if 32 <= (b ^ key) < 127 or (b ^ key) in (9, 10, 13)) \
                    / max(1, len(sample)) < 0.92:
                continue
            if time.monotonic() > deadline:
                break
            decoded = bytes(b ^ key for b in data)
            add(decoded.decode("latin-1"), f"xor1b(key=0x{key:02x})({origin})")
    for known in (b"flag", b"ctf", b"key", b"secret", b"password", origin.encode("utf-8", "replace")):
        if not known:
            continue
        decoded = bytes(b ^ known[i % len(known)] for i, b in enumerate(data))
        add(decoded.decode("latin-1"), f"xorkey({known!r})({origin})")

