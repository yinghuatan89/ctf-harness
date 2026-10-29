"""Forensics recipes: pcap scanning, file carving, memory-dump string hints."""

from __future__ import annotations

import re
from pathlib import Path

from .base import Recipe

_STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")
_CARBON_MAGICS = (
    (b"\x89PNG\r\n\x1a\n", ".png", "png"),
    (b"\xff\xd8\xff", ".jpg", "jpeg"),
    (b"PK\x03\x04", ".zip", "zip"),
    (b"%PDF", ".pdf", "pdf"),
    (b"\x1f\x8b", ".gz", "gzip"),
    (b"SQLite format 3\x00", ".sqlite", "sqlite"),
)


class PcapScanRecipe(Recipe):
    id = "forensics.pcap_scan"
    title = "Scan captures for flags, HTTP URIs, credentials"
    categories = ("forensics", "misc")

    def match(self, challenge) -> bool:
        return any(path.suffix.lower() in (".pcap", ".pcapng", ".cap")
                   for path in list(challenge.iter_files())[:50])

    def run(self, rc) -> list:
        outputs: list[str] = []
        for path in list(rc.challenge.iter_files())[:5]:
            if path.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
                continue
            try:
                data = path.read_bytes()[:20_000_000]
            except OSError:
                continue
            text = data.decode("latin-1")
            outputs.append(text)
            strings = "\n".join(m.group(0).decode("latin-1") for m in _STRING_RE.finditer(data))
            outputs.append(strings)
            uris = re.findall(rb"(?:GET|POST|PUT) ([!-~]{1,200}) HTTP", data)[:30]
            if uris:
                rc.note("HTTP URIs in capture: " +
                        "; ".join(u.decode("latin-1") for u in uris[:15]), tag="forensics")
            creds = re.findall(rb"pass(?:word|wd)?=([^&\s]{2,64})", data)[:10]
            if creds:
                rc.note("password-looking params: " +
                        "; ".join(c.decode("latin-1") for c in creds[:5]), tag="forensics")
            basics = re.findall(rb"Authorization: Basic ([A-Za-z0-9+/=]{8,})", data)[:10]
            import base64
            for basic in basics:
                try:
                    outputs.append(base64.b64decode(basic).decode("latin-1"))
                except Exception:  # noqa: BLE001
                    pass
        return rc.scan(*outputs)


class FileCarveRecipe(Recipe):
    id = "forensics.file_carve"
    title = "Carve embedded PNG/JPEG/ZIP/PDF/SQLite blobs out of carrier files"
    categories = ("forensics", "misc")

    def match(self, challenge) -> bool:
        return True

    def run(self, rc) -> list:
        outputs: list[str] = []
        carved_dir = rc.tool_ctx.workspace / "carved"
        carved_dir.mkdir(parents=True, exist_ok=True)
        counter = 0
        for path in list(rc.challenge.iter_files())[:10]:
            try:
                data = path.read_bytes()[:10_000_000]
            except OSError:
                continue
            if data.startswith((b"\x89PNG", b"\xff\xd8\xff", b"PK\x03\x04")):
                continue  # already that format, not a carrier
            for magic, ext, kind in _CARBON_MAGICS:
                start = 0
                hits = 0
                while hits < 5:
                    pos = data.find(magic, start)
                    if pos == -1 or pos == 0:
                        break
                    end = len(data)
                    if kind == "png":
                        iend = data.find(b"IEND", pos)
                        end = iend + 8 if iend != -1 else min(pos + 1_000_000, len(data))
                    elif kind == "jpeg":
                        eoi = data.find(b"\xff\xd9", pos)
                        end = eoi + 2 if eoi != -1 else min(pos + 1_000_000, len(data))
                    elif kind == "pdf":
                        eot = data.rfind(b"%%EOF")
                        end = eot + 5 if eot > pos else min(pos + 2_000_000, len(data))
                    blob = data[pos:min(end, pos + 2_000_000)]
                    counter += 1
                    target = carved_dir / f"carved_{counter:02d}{ext}"
                    target.write_bytes(blob)
                    rc.note(f"carved {kind} from {path.name} at offset {pos} "
                            f"-> {target.name}", tag="forensics")
                    outputs.append(blob.decode("latin-1"))
                    start = pos + len(magic)
                    hits += 1
        return rc.scan(*outputs)


class MemoryHintsRecipe(Recipe):
    id = "forensics.memory_hints"
    title = "Sample large binary dumps for interesting strings"
    categories = ("forensics", "misc")

    def match(self, challenge) -> bool:
        for path in list(challenge.iter_files())[:10]:
            try:
                if path.stat().st_size > 8_000_000:
                    return True
            except OSError:
                continue
        return False

    def run(self, rc) -> list:
        outputs: list[str] = []
        for path in list(rc.challenge.iter_files())[:5]:
            try:
                size = path.stat().st_size
                if size <= 8_000_000:
                    continue
                with path.open("rb") as handle:
                    head = handle.read(2_000_000)
                    handle.seek(max(0, size // 2))
                    middle = handle.read(2_000_000)
            except OSError:
                continue
            for label, chunk in (("head", head), ("middle", middle)):
                strings = "\n".join(
                    m.group(0).decode("latin-1")
                    for m in _STRING_RE.finditer(chunk))
                interesting = [line for line in strings.splitlines()
                               if re.search(r"(?i)flag|passw|secret|credential|admin|token",
                                            line)][:20]
                if interesting:
                    rc.note(f"{path.name} {label}: {len(interesting)} interesting strings, "
                            f"first: {interesting[0][:100]!r}", tag="forensics")
                    outputs.extend(interesting)
        return rc.scan(*outputs)


def forensics_recipes() -> list[Recipe]:
    return [
        PcapScanRecipe(PcapScanRecipe.id, PcapScanRecipe.title,
                       ("forensics", "misc"), "pcap flag/cred scan"),
        FileCarveRecipe(FileCarveRecipe.id, FileCarveRecipe.title,
                        ("forensics", "misc"), "carve embedded files"),
        MemoryHintsRecipe(MemoryHintsRecipe.id, MemoryHintsRecipe.title,
                          ("forensics", "misc"), "memory dump strings"),
    ]
