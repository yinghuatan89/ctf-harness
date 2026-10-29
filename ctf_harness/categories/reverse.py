"""Reverse playbook: static-first, patch/check bypass, dynamic confirmation."""

from __future__ import annotations

from .base import Playbook, _file_heads, _has_ext


class ReversePlaybook(Playbook):
    id = "reverse"
    title = "Reverse engineering"

    def matches(self, challenge) -> float:
        if challenge.remote:
            return 0.0  # ELF + remote is pwn, not reverse
        if _has_ext(challenge, (".apk", ".jar", ".pyc", ".exe", ".dll", ".so",
                                ".bin", ".elf", ".out")):
            return 0.8
        if any(head.startswith(b"\x7fELF") for _p, head in _file_heads(challenge, 40)):
            return 0.7
        if _has_ext(challenge, (".apk", ".jar")):
            return 0.75
        return 0.0

    def seed_hypotheses(self, challenge) -> list[str]:
        return [
            "strings + section/entry recon, identify language and packer; then "
            "decompile the main check function and read its logic.",
            "The flag is usually DERIVED, not stored: find the transform and "
            "invert it (write the keygen in python).",
            "If a VM/bytecode interpreter is present, dump the opcode stream "
            "and write a disassembler for it.",
        ]

    def system_prompt(self, challenge) -> str:
        return """## REVERSE METHODOLOGY
1. TRIAGE: strings (interesting ones already in notes), identify packer
   (UPX! magic -> unpack with upx -d), language runtime (Go/Rust/PyInstaller/
   Nuitka/.NET), architecture. PyInstaller -> extract with pyinstxtractor
   logic in python; .NET -> decompile IL.
2. STATIC FIRST: decompile main and any check/validate/license functions
   (ghidra headless / objdump / radare2 are listed in recon if installed).
   Understand: input format, the comparison target, the transform chain.
3. COMMON PATTERNS:
   - direct strcmp with hidden string (xored/stack-built) -> reconstruct it;
   - keygen math (modular arithmetic, LCG, matrix ops) -> re-implement in
     python and generate valid keys;
   - VM obfuscation (opcode dispatch loop) -> dump handlers, write a
     disassembler, trace the flag check path;
   - anti-debug (ptrace checks, timing, int3, IsDebuggerPresent) -> patch
     them out in a copy or avoid dynamic analysis entirely;
   - STM32/embedded firmware -> check for obvious xored flag blobs too.
4. DYNAMIC CONFIRMATION: when the check is too complex, patch the binary
   (flip the conditional jump in a copy inside the workspace) and run it;
   or emulate with unicorn/qiling-style python if available - otherwise
   pure-python reimplementation is usually faster.
5. Iterate: notes every intermediate conclusion (addresses, constants,
   pseudo-code) - the flag usually falls out of the derivation, and the
   writeup needs the chain anyway."""