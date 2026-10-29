"""Misc recipes: image steg (pure-python PNG LSB), zero-width, Brainfuck,
git history mining, known-plaintext XOR.

These cover the most common 'misc' archetypes seen in recent CTFs without
requiring any external tool; when zsteg/steghide/git ARE installed the
recipes also leverage them.
"""

from __future__ import annotations

import re
import shutil
import zlib
from pathlib import Path

from .base import Recipe

_BF_CHARS = set("+-<>[].,")


def _png_chunks(data: bytes):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    pos = 8
    chunks: list[tuple[bytes, bytes]] = []
    trailing = b""
    while pos + 8 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        chunks.append((ctype, body))
        pos += 12 + length
        if ctype == b"IEND":
            trailing = data[pos:]
            break
    return chunks, trailing


def _png_lsb_payloads(data: bytes, max_output: int = 65536):
    """Decode PNG pixel data and yield LSB-extracted byte blobs."""
    parsed = _png_chunks(data)
    if not parsed:
        return
    chunks, _trailing = parsed
    ihdr = next((body for ctype, body in chunks if ctype == b"IHDR"), None)
    if ihdr is None or len(ihdr) < 10:
        return
    width = int.from_bytes(ihdr[0:4], "big")
    height = int.from_bytes(ihdr[4:8], "big")
    bit_depth, color_type = ihdr[8], ihdr[9]
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type)
    if bit_depth != 8 or not channels or width <= 0 or height <= 0:
        return
    if width * height * channels > 8_000_000:
        return
    idat = b"".join(body for ctype, body in chunks if ctype == b"IDAT")
    try:
        raw = zlib.decompress(idat)
    except zlib.error:
        return
    stride = width * channels
    if len(raw) < height * (stride + 1):
        height = len(raw) // (stride + 1)
    pixels = bytearray()
    prev = bytearray(stride)
    pos = 0
    for _y in range(height):
        filter_type = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        if filter_type == 1:
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif filter_type == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif filter_type == 3:
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif filter_type == 4:
            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                b = prev[i]
                c = prev[i - channels] if i >= channels else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        pixels += line
        prev = line
    for bitpos in (0, 1):
        bits = bytearray()
        total_bits = max_output * 8
        for byte in pixels:
            bits.append((byte >> bitpos) & 1)
            if len(bits) >= total_bits:
                break
        blob = bytes(
            int("".join(map(str, bits[i:i + 8])), 2)
            for i in range(0, len(bits) // 8 * 8, 8))
        yield f"lsb bit{bitpos}", blob


def _jpeg_parts(data: bytes):
    trailing = b""
    last = data.rfind(b"\xff\xd9")
    if last != -1 and last + 2 < len(data) - 1:
        trailing = data[last + 2:]
    comments = []
    pos = 0
    while pos + 4 <= len(data):
        if data[pos:pos + 2] in (b"\xff\xfe", b"\xff\xe2", b"\xff\xe1") and data[pos:pos+2] == b"\xff\xfe":
            length = int.from_bytes(data[pos + 2:pos + 4], "big")
            comments.append(data[pos + 4:pos + 2 + length])
            pos += 2 + length
        else:
            pos += 1
    return trailing, comments


class StegProbeRecipe(Recipe):
    id = "misc.steg_probe"
    title = "Image steg: PNG LSB decode, trailing data, JPEG comments, zsteg/steghide"
    categories = ("misc", "forensics")

    def match(self, challenge) -> bool:
        for path in list(challenge.iter_files())[:30]:
            try:
                head = path.read_bytes()[:16]
            except OSError:
                continue
            if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM")):
                return True
        return False

    def run(self, rc) -> list:
        outputs: list[str] = []
        for path in list(rc.challenge.iter_files())[:10]:
            try:
                data = path.read_bytes()[:10_000_000]
            except OSError:
                continue
            name = path.name
            if data.startswith(b"\x89PNG"):
                parsed = _png_chunks(data)
                if parsed:
                    chunks, trailing = parsed
                    for ctype, body in chunks:
                        if ctype in (b"tEXt", b"zTXt", b"iTXt"):
                            outputs.append(body.decode("latin-1"))
                            rc.note(f"PNG {ctype.decode()} chunk in {name}: "
                                    f"{body[:120]!r}", tag="steg")
                    if trailing and len(trailing) > 4:
                        rc.note(f"PNG trailing data after IEND in {name}: "
                                f"{len(trailing)} bytes", tag="steg")
                        outputs.append(trailing.decode("latin-1"))
                    for label, blob in _png_lsb_payloads(data):
                        text = blob.decode("latin-1")
                        outputs.append(text)
                        rc.note(f"PNG {label} extraction of {name} produced "
                                f"{len(blob)} bytes", tag="steg")
            elif data.startswith(b"\xff\xd8\xff"):
                trailing, comments = _jpeg_parts(data)
                for comment in comments:
                    outputs.append(comment.decode("latin-1"))
                if trailing:
                    rc.note(f"JPEG trailing data after EOI in {name}: "
                            f"{len(trailing)} bytes", tag="steg")
                    outputs.append(trailing.decode("latin-1"))
        found = rc.scan(*outputs)
        if found:
            return found
        # leverage external tools when present
        for tool, args in (("zsteg", "-a"), ("steghide", "info")):
            if shutil.which(tool):
                for path in list(rc.challenge.iter_files())[:3]:
                    if path.suffix.lower() not in (".png", ".jpg", ".jpeg", ".bmp"):
                        continue
                    result = rc.dispatch("shell", cmd=f"{tool} {args} \"{path}\"",
                                        timeout=30)
                    outputs.append(result.output or "")
        return rc.scan(*outputs)


class ZeroWidthRecipe(Recipe):
    id = "misc.zero_width"
    title = "Decode zero-width character steg (U+200B/200C binary)"
    categories = ("misc", "forensics", "crypto")

    _MAP = {"\u200b": "0", "\u200c": "1"}

    def match(self, challenge) -> bool:
        for path in list(challenge.iter_files())[:20]:
            try:
                raw = path.read_bytes()[:200_000].decode("utf-8", "replace")
            except OSError:
                continue
            if any(char in raw for char in self._MAP):
                return True
        return False

    def run(self, rc) -> list:
        outputs: list[str] = []
        for path in list(rc.challenge.iter_files())[:20]:
            try:
                raw = path.read_bytes()[:200_000].decode("utf-8", "replace")
            except OSError:
                continue
            bits = "".join(self._MAP.get(c, "") for c in raw)
            if bits:
                blob = bytes(int(bits[i:i + 8], 2)
                             for i in range(0, len(bits) // 8 * 8, 8))
                outputs.append(blob.decode("latin-1"))
                rc.note(f"zero-width steg: {len(bits)} bits in {path.name}", tag="steg")
        return rc.scan(*outputs)


class BrainfuckRecipe(Recipe):
    id = "misc.brainfuck"
    title = "Run Brainfuck/esoteric programs found in files"
    categories = ("misc", "reverse")

    def match(self, challenge) -> bool:
        for path in list(challenge.iter_files())[:10]:
            try:
                raw = path.read_bytes()[:100_000].decode("latin-1")
            except OSError:
                continue
            chars = [c for c in raw if not c.isspace()]
            if len(chars) >= 20 and sum(c in _BF_CHARS for c in chars) / len(chars) > 0.9:
                return True
        return False

    def run(self, rc) -> list:
        for path in list(rc.challenge.iter_files())[:5]:
            try:
                raw = path.read_bytes()[:100_000].decode("latin-1")
            except OSError:
                continue
            program = "".join(c for c in raw if c in _BF_CHARS)
            if len(program) < 20:
                continue
            code = f'''
import sys
prog = {program!r}
jumps = {{}}
stack = []
for i, c in enumerate(prog):
    if c == "[":
        stack.append(i)
    elif c == "]":
        j = stack.pop()
        jumps[j] = i
        jumps[i] = j
tape = [0] * 30000
ptr = 0
out = bytearray()
i = 0
steps = 0
while i < len(prog) and steps < 5_000_000:
    c = prog[i]
    steps += 1
    if c == ">":
        ptr = (ptr + 1) % 30000
    elif c == "<":
        ptr = (ptr - 1) % 30000
    elif c == "+":
        tape[ptr] = (tape[ptr] + 1) % 256
    elif c == "-":
        tape[ptr] = (tape[ptr] - 1) % 256
    elif c == ".":
        out.append(tape[ptr])
    elif c == "[" and tape[ptr] == 0:
        i = jumps[i]
    elif c == "]" and tape[ptr] != 0:
        i = jumps[i]
    i += 1
sys.stdout.write(out.decode("latin-1", "replace"))
'''
            result = rc.dispatch("run_python", code=code, timeout=60)
            found = rc.scan(result.output or "")
            if found:
                return found
        return []


class GitMiningRecipe(Recipe):
    id = "misc.git_mining"
    title = "Mine .git history for flags and leaks"
    categories = ("misc", "web", "forensics")

    def match(self, challenge) -> bool:
        return bool(rc_path_exists(challenge, ".git"))

    def run(self, rc) -> list:
        if not shutil.which("git"):
            rc.note("git not installed - cannot mine .git history", tag="warn")
            return []
        commands = ("git log --all --oneline", "git log --all -p",
                    "git stash list", "git show-ref --head")
        outputs = []
        for cmd in commands:
            result = rc.dispatch("shell", cmd=cmd, timeout=30)
            outputs.append(result.output or "")
        return rc.scan(*outputs)


class KnownPlaintextXorRecipe(Recipe):
    id = "misc.known_plaintext_xor"
    title = "Derive XOR key from assumed flag prefix and decrypt"
    categories = ("misc", "crypto")

    def match(self, challenge) -> bool:
        return True

    def run(self, rc) -> list:
        outputs = []
        for path in list(rc.challenge.iter_files())[:6]:
            try:
                data = path.read_bytes()[:64_000]
            except OSError:
                continue
            if not data:
                continue
            for guess in (b"flag{", b"ctf{", b"FLAG{", b"CTF{", b"flag"):
                key_len = len(guess)
                key = bytes(a ^ b for a, b in zip(data[:key_len], guess))
                decoded = bytes(b ^ key[i % key_len] for i, b in enumerate(data))
                outputs.append(decoded.decode("latin-1"))
        return rc.scan(*outputs)


def rc_path_exists(challenge, name: str) -> bool:
    if not challenge.path:
        return False
    root = Path(challenge.path)
    return (root / name).exists() or any(
        part == name for p in root.rglob(name) for part in p.parts)


def misc_recipes() -> list[Recipe]:
    return [
        StegProbeRecipe(StegProbeRecipe.id, StegProbeRecipe.title,
                        ("misc", "forensics"), "PNG LSB / trailing / comments"),
        ZeroWidthRecipe(ZeroWidthRecipe.id, ZeroWidthRecipe.title,
                        ("misc", "forensics", "crypto"), "zero-width unicode"),
        BrainfuckRecipe(BrainfuckRecipe.id, BrainfuckRecipe.title,
                        ("misc", "reverse"), "brainfuck interpreter"),
        GitMiningRecipe(GitMiningRecipe.id, GitMiningRecipe.title,
                        ("misc", "web", "forensics"), "git history mining"),
        KnownPlaintextXorRecipe(KnownPlaintextXorRecipe.id, KnownPlaintextXorRecipe.title,
                                ("misc", "crypto"), "known plaintext xor"),
    ]
