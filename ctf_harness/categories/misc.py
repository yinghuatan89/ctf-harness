"""Misc playbook: steg decision tree, esolangs, odd encodings, services."""

from __future__ import annotations

from .base import Playbook


class MiscPlaybook(Playbook):
    id = "misc"
    title = "Misc / steg / everything else"

    def matches(self, challenge) -> float:
        return 0.05  # the floor: misc is the fallback playbook

    def seed_hypotheses(self, challenge) -> list[str]:
        return [
            "Re-check every file with fresh eyes: trailing data, embedded "
            "archives, LSB, metadata - the automated pass already covered the "
            "classics, so look for the unusual detail (odd sizes, timestamps).",
            "If a remote service exists, connect and interact manually "
            "(banner, menu, protocol quirks) before assuming steg.",
            "Esoteric/encoded formats: brainfuck, JSFuck, Ook, morse, zero-width, "
            "custom base - identify then implement the decoder in python.",
        ]

    def system_prompt(self, challenge) -> str:
        return """## MISC METHODOLOGY
The harness already ran: encoding cascade (base64/32/hex/zip/gzip/tar),
Caesar, single-byte and known-key XOR, strings extraction; PNG LSB decode,
PNG/JPEG trailing data, zero-width unicode, brainfuck execution, git
history mining, known-plaintext XOR; pcap flag/credential scan, magic-based
carving, large-dump string hints. Read your notes before redoing any of it.

1. STEG DECISION TREE by file type:
   - images: LSB variants (bit order/channel order), appended archives,
     EXIF/comments, color-palette tricks, steghide/zsteg/stegsolve if
     installed; check whether the file is actually a polyglot;
   - audio: spectrogram view (sox/audacity when available), morse,
     LSB in samples, DTMF tones;
   - video/PDF: embedded files, frame diffing, base64 blobs;
   - archives: nested nesting chains, password from riddle text.
2. ESOLANGS & ODD FORMATS: brainfuck/JSFuck/Ook/piet/malbolge - identify
   from charset shape, then implement or reason; zero-width, tap code,
   bacon, morse, braille dot patterns.
3. REMOTE SERVICES: connect manually (python socket) - banner grabbing,
   menu logic, timing puzzles, text-adventure commands, math challenges.
4. RIDDLE TEXT: the challenge description itself often encodes the method
   (wordplay, first letters, counts). Extract and try systematically.
5. LAST RESORT HEURISTICS: hash-identified file fragments, unknown-binary
   entropy check (high entropy = encrypted/compressed), FFT on audio if
   numpy exists.
Work breadth-first: misc is won by recognizing the trick FAST, not by
deep-diving the first idea. Note every negative result too - elimination
is progress."""
