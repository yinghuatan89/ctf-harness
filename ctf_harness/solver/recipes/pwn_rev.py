"""Pwn/Reverse recipes: ELF recon (pure-python), ret2win hints, format-string
probe, UPX unpacking.

These mostly push *notes* onto the blackboard (protections, suspicious
symbols, format-string offset) so the L2 lanes skip half of the recon phase
and start at the exploitation step.
"""

from __future__ import annotations

import re
import shutil
import struct
from pathlib import Path

from .base import Recipe

_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")

_SUSPICIOUS = (b"win", b"backdoor", b"get_flag", b"getflag", b"flag.txt", b"/bin/sh",
               b"system", b"execve", b"shell", b"secret", b"cat ")

PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552


def _parse_elf(data: bytes) -> dict | None:
    if not data.startswith(b"\x7fELF") or len(data) < 64:
        return None
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    e_type = struct.unpack_from(endian + "H", data, 16)[0]
    info: dict = {
        "class": "ELF64" if is64 else "ELF32",
        "pie": e_type == 3,
        "e_type": {2: "EXEC (no PIE)", 3: "DYN (PIE)"}.get(e_type, str(e_type)),
        "canary": b"__stack_chk_fail" in data,
        "nx": None,
        "relro": "none",
    }
    if is64:
        phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        phentsize = struct.unpack_from(endian + "H", data, 54)[0]
        phnum = struct.unpack_from(endian + "H", data, 56)[0]
    else:
        phoff = struct.unpack_from(endian + "I", data, 28)[0]
        phentsize = struct.unpack_from(endian + "H", data, 42)[0]
        phnum = struct.unpack_from(endian + "H", data, 44)[0]
    exec_stack_seen = False
    gnu_stack_seen = False
    relro_seen = False
    for i in range(min(phnum, 64)):
        base = phoff + i * phentsize
        if base + 8 > len(data):
            break
        p_type = struct.unpack_from(endian + "I", data, base)[0]
        if p_type == PT_GNU_STACK:
            gnu_stack_seen = True
            flags = struct.unpack_from(endian + "I", data, base + 4)[0]
            exec_stack_seen = bool(flags & 1)
        elif p_type == PT_GNU_RELRO:
            relro_seen = True
    info["nx"] = (gnu_stack_seen and not exec_stack_seen)
    info["relro"] = "partial/full" if relro_seen else "none"
    return info


def _elf_paths(challenge, limit: int = 5) -> list[Path]:
    out = []
    for path in list(challenge.iter_files())[:60]:
        try:
            head = path.read_bytes()[:4]
        except OSError:
            continue
        if head == b"\x7fELF":
            out.append(path)
            if len(out) >= limit:
                break
    return out


class ElfReconRecipe(Recipe):
    id = "pwn.elf_recon"
    title = "ELF protections recon (PIE/NX/canary/RELRO) + suspicious symbols"
    categories = ("pwn", "reverse")

    def match(self, challenge) -> bool:
        return bool(_elf_paths(challenge))

    def run(self, rc) -> list:
        outputs: list[str] = []
        for path in _elf_paths(rc.challenge):
            try:
                data = path.read_bytes()[:5_000_000]
            except OSError:
                continue
            info = _parse_elf(data)
            if not info:
                continue
            rc.note(
                f"{path.name}: {info['class']}, {info['e_type']}, "
                f"NX={'on' if info['nx'] else 'off'}, "
                f"Canary={'on' if info['canary'] else 'off'}, "
                f"RELRO={info['relro']}", tag="pwn")
            strings = [m.group(0).decode("latin-1")
                       for m in _STRING_RE.finditer(data[:1_000_000])]
            hits = [s for s in strings if any(k in s.lower() for k in
                    ("win", "backdoor", "flag", "shell", "secret", "/bin/sh"))][:12]
            if hits:
                rc.note(f"{path.name} suspicious strings: {hits}", tag="pwn")
                outputs.extend(hits)
            outputs.append("\n".join(strings[:500]))
            if shutil.which("checksec"):
                result = rc.dispatch("shell", cmd=f"checksec --file={path}", timeout=20)
                outputs.append(result.output or "")
        return rc.scan(*outputs)


class FormatStringProbeRecipe(Recipe):
    id = "pwn.fmt_probe"
    title = "Probe remote service for format-string echoes (%p)"
    categories = ("pwn",)

    def match(self, challenge) -> bool:
        return bool(challenge.remote)

    def run(self, rc) -> list:
        remote = rc.challenge.remote
        if not remote or ":" not in remote:
            return []
        host, _, port = remote.rpartition(":")
        if not host or not port.isdigit():
            return []
        code = f'''
import socket
host, port = {host!r}, {int(port)}
payloads = [b"AAAA%7$p", b"AAAA%8$p", b"AAAA%9$p", b"AAAA%10$p",
            b"AAAA%11$p", b"AAAA%12$p", b"AAAA" + b"%p." * 6]
for payload in payloads:
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(payload + b"\\n")
        data = s.recv(4096)
        s.close()
    except OSError as exc:
        print("err", exc)
        continue
    print(payload, "->", data[:300])
'''
        result = rc.dispatch("run_python", code=code, timeout=90)
        text = result.output or ""
        if "0x" in text:
            rc.note("format-string echo detected (%p prints pointers); "
                    "offset candidates visible in probe output", tag="pwn")
        return rc.scan(text)


class UpxUnpackRecipe(Recipe):
    id = "pwn.upx_unpack"
    title = "Unpack UPX-packed binaries, then re-scan strings"
    categories = ("pwn", "reverse")

    def match(self, challenge) -> bool:
        return any(_is_upx(p) for p in _elf_paths(challenge))

    def run(self, rc) -> list:
        outputs: list[str] = []
        for path in _elf_paths(rc.challenge):
            if not _is_upx(path):
                continue
            if not shutil.which("upx"):
                rc.note(f"{path.name} is UPX-packed but 'upx' is not installed "
                        f"(pip-install nothing; apt install upx-ucl)", tag="warn")
                continue
            result = rc.dispatch("shell", cmd=f"upx -d -o \"{path}.unpacked\" \"{path}\"",
                                 timeout=30)
            outputs.append(result.output or "")
            unpacked = Path(str(path) + ".unpacked")
            if unpacked.exists():
                data = unpacked.read_bytes()[:2_000_000]
                strings = "\n".join(m.group(0).decode("latin-1")
                                   for m in _STRING_RE.finditer(data))
                outputs.append(strings)
        return rc.scan(*outputs)


def _is_upx(path: Path) -> bool:
    try:
        return b"UPX!" in path.read_bytes()[:100_000]
    except OSError:
        return False


def pwn_rev_recipes() -> list[Recipe]:
    return [
        ElfReconRecipe(ElfReconRecipe.id, ElfReconRecipe.title,
                       ("pwn", "reverse"), "protections + symbols"),
        FormatStringProbeRecipe(FormatStringProbeRecipe.id, FormatStringProbeRecipe.title,
                                 ("pwn",), "remote %p probe"),
        UpxUnpackRecipe(UpxUnpackRecipe.id, UpxUnpackRecipe.title,
                        ("pwn", "reverse"), "UPX unpack"),
    ]
