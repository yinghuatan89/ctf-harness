"""Offline selftest: proves the whole pipeline works without any API key.

Stages:
  1. L0 heuristic solves (base64 / caesar / single-byte XOR bundles)
  2. L1 recipe solve (RSA small-e challenge, pure-python attack kit)
  3. L1 web recipe solve (SQLi auth bypass against a bundled local service)
  4. L2 supervisor E2E (mock supervisor + mock executor sub-agents find a
     hidden route; exercises Supervisor -> SpecialistRunner -> report/flag
     harvest -> scorer verification with zero real model calls)
"""

from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .config import DEFAULT_CONFIG, deep_merge
from .core.challenge import Challenge
from .core.orchestrator import Orchestrator, SolveOptions
from .llm import Router
from .plugins import PluginRegistry

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
CHALLENGES = EXAMPLES / "challenges"

FLAGS = {
    "base64": "flag{b64_nested_encoding}",
    "caesar": "flag{caesar_is_classic}",
    "xor": "flag{xor_single_byte_pwned}",
    "rsa": "flag{rsa_small_e_cube_root}",
    "sqli": "flag{sql_injection_bypass_pwned}",
    "supervisor": "flag{supervisor_hidden_route_win}",
}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_server(port: int) -> subprocess.Popen:
    server = CHALLENGES / "web_sqli" / "server.py"
    proc = subprocess.Popen(
        [sys.executable, str(server), str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return proc
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError("bundled web server exited at startup")
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("bundled web server did not start in time")


def _solve(cfg, challenge, workdir, **opt_overrides):
    orchestrator = Orchestrator(cfg, plugins=PluginRegistry(), kb=None, out=lambda *_: None)
    opts = SolveOptions.from_config(cfg, **opt_overrides)
    return orchestrator.solve(challenge, opts, run_dir=workdir)


def run_selftest() -> int:
    print(f"ctf-harness selftest (offline, no API keys needed)")
    checks: list[tuple[str, bool, str]] = []
    work = Path(tempfile.mkdtemp(prefix="ctfh-selftest-"))

    # ---- 1. L0 heuristic solves ------------------------------------------- #
    for folder, key in (("misc_base64", "base64"),
                        ("crypto_caesar", "caesar"),
                        ("misc_xor", "xor")):
        cfg = deep_merge(DEFAULT_CONFIG, {"solve": {"mode": "single"}})
        challenge = Challenge(name=folder, path=CHALLENGES / folder,
                               category="misc")
        result = _solve(cfg, challenge, work / folder, use_llm=False,
                        time_budget_s=60, fast=True, fast_budget_s=15,
                        recipe_budget_s=10)
        checks.append((f"L0 heuristics [{folder}]",
                       result.solved and result.flag == FLAGS[key],
                       f"flag={result.flag} via={result.via}"))

    # ---- 2. L1 recipe: RSA small-e ---------------------------------------- #
    cfg = deep_merge(DEFAULT_CONFIG, {"solve": {"mode": "single"}})
    challenge = Challenge(name="crypto_rsa_small_e",
                          path=CHALLENGES / "crypto_rsa_small_e",
                          category="crypto")
    result = _solve(cfg, challenge, work / "rsa", use_llm=False,
                    time_budget_s=90, fast=True, fast_budget_s=10,
                    recipe_budget_s=60)
    checks.append(("L1 recipe [crypto.rsa_attacks]",
                   result.solved and result.flag == FLAGS["rsa"],
                   f"flag={result.flag} via={result.via} recipes={result.recipes_executed}"))

    # ---- 3. L1 web recipe: SQLi bypass ------------------------------------ #
    port = _free_port()
    server = _start_server(port)
    try:
        base = f"http://127.0.0.1:{port}"
        cfg = deep_merge(DEFAULT_CONFIG, {"solve": {"mode": "single"}})
        challenge = Challenge(name="web_sqli", path=None, category="web",
                              url=f"{base}/", scorer=f"{base}/check")
        result = _solve(cfg, challenge, work / "web_sqli", use_llm=False,
                        time_budget_s=90, fast=True, fast_budget_s=5,
                        recipe_budget_s=45)
        checks.append(("L1 recipe [web.sqli_bypass]",
                       result.solved and result.flag == FLAGS["sqli"],
                       f"flag={result.flag} via={result.via}"))

        # ---- 4. L2 supervisor E2E with mock models ------------------------ #
        cfg2 = deep_merge(DEFAULT_CONFIG, {
            "providers": {
                "mock_sup": {"type": "mock", "model": "mock-supervisor",
                             "script": str(EXAMPLES / "mock" / "supervisor_script.jsonl")},
                "mock_exec": {"type": "mock", "model": "mock-executor",
                              "script": str(EXAMPLES / "mock" / "web_executor_script.jsonl"),
                              "vars": {"PORT": port}},
            },
            "roles": {"supervisor": {"provider": "mock_sup"},
                      "strategist": {"provider": "mock_sup"},
                      "reflector": {"provider": "mock_sup"},
                      "executor": {"provider": "mock_exec"}},
            "solve": {"mode": "supervisor", "supervisor_rounds": 2,
                      "subagent_steps": 4, "subagents_parallel": 2},
        })
        router = Router(cfg2)
        orchestrator = Orchestrator(cfg2, router=router, plugins=PluginRegistry(),
                                    kb=None, out=lambda *_: None)
        challenge2 = Challenge(name="web_hidden_route", path=None,
                               category="web", url=f"{base}/noform",
                               scorer=f"{base}/check")
        opts = SolveOptions.from_config(cfg2, time_budget_s=120, fast=False)
        result2 = orchestrator.solve(challenge2, opts, run_dir=work / "supervisor")
        checks.append(("L2 supervisor E2E (mock models)",
                       result2.solved and result2.flag == FLAGS["supervisor"],
                       f"flag={result2.flag} via={result2.via} lanes="
                       f"{len(result2.lanes)}"))
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()

    # ---- report ----------------------------------------------------------- #
    print()
    all_ok = True
    for name, ok, detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")
        all_ok = all_ok and ok
    print(f"\nselftest result: {'ALL PASS' if all_ok else 'FAILURES PRESENT'}")
    print(f"workdir: {work}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(run_selftest())
