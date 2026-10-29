"""Pwn playbook: checksec -> vuln class -> scripted exploit -> remote."""

from __future__ import annotations

from .base import Playbook, _file_heads


class PwnPlaybook(Playbook):
    id = "pwn"
    title = "Binary exploitation (pwn)"

    def matches(self, challenge) -> float:
        has_elf = any(head.startswith(b"\x7fELF")
                      for _p, head in _file_heads(challenge, 40))
        if has_elf and challenge.remote:
            return 0.95
        if has_elf:
            return 0.35
        if challenge.remote and not challenge.files:
            return 0.4
        return 0.0

    def seed_hypotheses(self, challenge) -> list[str]:
        return [
            "checksec + decompile main; find the vuln function; if a win/"
            "backdoor function exists, overflow straight into it (ret2win).",
            "Leak first: puts(printf GOT) or format string %p to defeat "
            "ASLR/PIE, then ret2libc / one_gadget.",
            "If heap service: identify malloc/free bugs (double free, UAF, "
            "overflow), then tcache poisoning (glibc>=2.32: fd^=addr>>12).",
        ]

    def system_prompt(self, challenge) -> str:
        return f"""## PWN METHODOLOGY
1. RECON (the harness already parsed protections - read your notes):
   PIE/NX/canary/RELRO change the exploit plan. Look for suspicious symbols
   (win/backdoor/getflag) and useful strings (/bin/sh, flag.txt).
2. FIND THE BUG: decompile with the best available tool (ghidra headless,
   objdump, radare2). Focus on reads into fixed buffers (gets/scanf/read),
   format strings (printf(user_input)), off-by-one, UAF/double-free in menu
   services, arbitrary write via index without bounds checks.
3. EXPLOIT CLASSES:
   - Stack overflow: cyclic pattern for the offset; ret2win if symbol
     exists; else leak (puts@plt with a GOT/ret ropchain) -> ret2libc:
     compute libc base = leak - known_offset, then system("/bin/sh") or
     one_gadget. NX forces ROP; no PIE makes gadgets static.
   - Format string: iterate %p to find your buffer offset; leaks first,
     then writes with %n (target via stack/arg chain); full RELRO blocks
     GOT overwrite -> target hooks/return addresses instead.
   - Heap (glibc 2.31+: tcache; 2.32+: safe-linking fd = target ^ (heap>>12)):
     tcache poisoning after UAF/double-free; unsorted-bin leak (main_arena);
     house-of techniques when size checks matter; FSOP on exit handlers for
     full protections.
   - seccomp/NoExec: open-read-write ROP chain, or ORW via one_gadget style
     when sockets are pre-connected.
4. WORKFLOW: write the exploit with run_python (socket/pwntools if
   installed) against the LOCAL binary first, iterate until stable, then
   point it at the remote host:port. Save every version - it goes into the
   writeup. Expect 2-3 iterations; keep sends/receives in sync with the
   service prompts (recv until the menu/confirmation appears).
5. If the service is a one-shot guesser (no bug found), reconsider: maybe
   it is reverse/protocol puzzle, or the bug is in the parser (try length
   prefix confusion, negative sizes).""" + (
            f"\nRemote service: {challenge.remote} - exploit must work there."
            if challenge.remote else "")
