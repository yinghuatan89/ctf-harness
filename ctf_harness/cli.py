"""ctfh - the CTF harness command line interface.

    ctfh solve ./challenge --url http://... --category web
    ctfh solve ./chall --remote 1.2.3.4:1337 --mode supervisor
    ctfh rush --ctfd https://ctf.example.com --token ... --submit
    ctfh selftest          # offline end-to-end test, no API keys needed
    ctfh models --ping     # pre-race warmup: provider latency table
    ctfh doctor            # environment checkup
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import __version__
from .config import load_config
from .core.challenge import Challenge, DEFAULT_FLAG_RE, extract_hosts
from .core.orchestrator import Orchestrator, SolveOptions
from .kb import KnowledgeBase, default_kb_dirs
from .llm import Router
from .plugins import load_plugins
from .solver.recipes import all_recipes

_PRINT_LOCK = threading.Lock()


def _say(*parts) -> None:
    with _PRINT_LOCK:
        print(*parts, flush=True)


# ---------------------------------------------------------------------------- #
# single solve
# ---------------------------------------------------------------------------- #
def _build_challenge(args) -> Challenge:
    path = Path(args.path) if getattr(args, "path", None) else None
    name = getattr(args, "name", None) or (path.name if path else "challenge")
    return Challenge(
        name=name,
        category=getattr(args, "category", None),
        path=path,
        url=getattr(args, "url", None),
        remote=getattr(args, "remote", None),
        scorer=getattr(args, "scorer", None),
        flag_format=getattr(args, "flag_format", None) or DEFAULT_FLAG_RE,
        extra_hosts=list(getattr(args, "allow_host", None) or []),
    )


def _print_result(result) -> None:
    badge = "SOLVED" if result.solved else result.status.upper()
    _say(f"[{badge}] {result.name}  flag={result.flag or '-'}  "
         f"via={result.via or '-'}  time={result.duration_s}s")
    for entry in getattr(result, "lanes", []) or []:
        if hasattr(entry, "summary_line"):
            _say(f"    - {entry.summary_line()}")
        else:
            lane = getattr(entry, "lane_id", "?")
            info = getattr(entry, "last_error", "") or getattr(entry, "conclusion", "")
            _say(f"    - {lane}: {str(info)[:160]}")
    if getattr(result, "recipes_executed", None):
        _say(f"    recipes: {', '.join(result.recipes_executed)}")
    if result.writeup_path:
        _say(f"    writeup: {result.writeup_path}")
    if result.error:
        _say(f"    error: {result.error}")


def _solve_options(cfg, args, *, interactive=False) -> SolveOptions:
    return SolveOptions.from_config(
        cfg,
        mode=getattr(args, "mode", None),
        max_steps=getattr(args, "max_steps", None),
        time_budget_s=getattr(args, "time_budget", None),
        lanes=getattr(args, "lanes", None),
        use_llm=not getattr(args, "no_llm", False),
        fast=not getattr(args, "no_fast", False),
        interactive=interactive,
    )


def cmd_solve(args, cfg, plugins, kb) -> int:
    challenge = _build_challenge(args)
    if not challenge.path and not challenge.url and not challenge.remote:
        print("error: provide a challenge path, --url and/or --remote")
        return 2
    orchestrator = Orchestrator(cfg, plugins=plugins, kb=kb, out=_say)
    opts = _solve_options(cfg, args, interactive=getattr(args, "interactive", False))
    run_dir = Path(args.run_dir) if getattr(args, "run_dir", None) else None
    result = orchestrator.solve(challenge, opts, run_dir=run_dir)
    _print_result(result)
    if getattr(args, "json", False):
        print(json.dumps({
            "name": result.name, "status": result.status, "flag": result.flag,
            "via": result.via, "duration_s": result.duration_s,
            "writeup": result.writeup_path}, ensure_ascii=False))
    return 0 if result.solved else 1


# ---------------------------------------------------------------------------- #
# rush: whole-competition batch mode
# ---------------------------------------------------------------------------- #
_CATEGORY_PRIORITY = {"web": 0, "misc": 1, "crypto": 2, "forensics": 3,
                      "reverse": 4, "pwn": 5}


def _rush_targets(args, cfg):
    """Return [(challenge, ctfd_meta|None)] to solve."""
    from .categories import normalize_category
    targets = []
    if args.ctfd:
        from .ctfd.client import CTFdClient
        token = args.token or cfg.get("ctfd", {}).get("token")
        cookie = cfg.get("ctfd", {}).get("cookie")
        client = CTFdClient(args.ctfd, token=token, cookie=cookie)
        _say(f"[rush] syncing challenges from {args.ctfd} ...")
        for item in client.list_challenges():
            if item.get("state") and str(item["state"]) != "visible":
                continue
            try:
                details = client.get_challenge(item["id"])
            except Exception as exc:  # noqa: BLE001
                _say(f"[rush] cannot sync #{item['id']} {item.get('name')}: {exc}")
                continue
            slug = "".join(c if c.isalnum() else "_" for c in str(item["name"]))[:50]
            dest = Path(args.run_root) / "challenges" / slug
            for file_url in details.get("files") or []:
                try:
                    client.download_file(file_url, dest / Path(file_url).name)
                except Exception as exc:  # noqa: BLE001
                    _say(f"[rush] file download failed for {slug}: {exc}")
            description = str(details.get("description") or "")
            urls = extract_hosts(description)
            targets.append((
                Challenge(name=str(item["name"]),
                          category=normalize_category(item.get("category")),
                          path=dest if dest.exists() else None,
                          description=description,
                          url=f"http://{urls[0]}" if urls and not description.lower().count("http") else None,
                          challenge_id=item["id"]),
                {"client": client, "points": item.get("value") or 0}))
    elif args.dir:
        root = Path(args.dir)
        if not root.is_dir():
            print(f"error: {args.dir} is not a directory")
            sys.exit(2)
        for folder in sorted(root.iterdir()):
            if not folder.is_dir():
                continue
            description = ""
            for readme in ("README.md", "readme.md", "README.txt", "描述.txt"):
                candidate = folder / readme
                if candidate.is_file():
                    description = candidate.read_text(encoding="utf-8",
                                                     errors="replace")[:600]
                    break
            category = normalize_category(folder.name.split("_")[0].lower())
            targets.append((Challenge(name=folder.name, category=category,
                                       path=folder, description=description), None))
    if args.order == "name":
        targets.sort(key=lambda pair: pair[0].name.lower())
    elif args.order == "easiest":
        targets.sort(key=lambda pair: _CATEGORY_PRIORITY.get(pair[0].category or "misc", 3))
    else:  # points: value desc, unknown last
        targets.sort(key=lambda pair: -(pair[1] or {}).get("points", 0) if pair[1] else 1)
    return targets


def cmd_rush(args, cfg, plugins, kb) -> int:
    targets = _rush_targets(args, cfg)
    if not targets:
        print("no challenges found - check --ctfd/--dir")
        return 2
    _say(f"[rush] {len(targets)} challenges, {args.workers} parallel workers, "
         f"submit={'ON' if args.submit else 'off'}")
    orchestrator = Orchestrator(cfg, plugins=plugins, kb=kb, out=_say,
                                run_root=Path(args.run_root))
    base_opts = _solve_options(cfg, args)
    submit_lock = threading.Lock()
    solved_any = threading.Event()

    def worker(index, challenge, ctfd_meta):
        opts = SolveOptions.from_config(
            cfg, mode=base_opts.mode,
            time_budget_s=min(base_opts.time_budget_s, args.time_budget))
        run_dir = Path(args.run_root) / "runs" / f"{index:02d}_{challenge.name[:40]}"
        result = orchestrator.solve(challenge, opts, run_dir=run_dir)
        if result.solved and args.submit and ctfd_meta and ctfd_meta.get("client"):
            with submit_lock:
                try:
                    outcome = ctfd_meta["client"].submit_flag(
                        challenge.challenge_id, result.flag)
                    _say(f"[submit] {challenge.name}: {outcome['status']} "
                         f"- {outcome['message']}")
                except Exception as exc:  # noqa: BLE001
                    _say(f"[submit] {challenge.name} failed: {exc}")
        if result.solved:
            solved_any.set()
        return result

    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {pool.submit(worker, i, ch, meta): ch
                   for i, (ch, meta) in enumerate(targets)}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                _say(f"[rush] worker crashed: {exc}")

    _say("")
    _say("[rush] summary")
    _say(f"{'challenge':40} {'status':10} {'flag':36} time")
    for result in sorted(results, key=lambda r: r.name.lower()):
        _say(f"{result.name[:40]:40} {result.status:10} "
             f"{(result.flag or '-')[:36]:36} {result.duration_s}s")
    return 0 if solved_any.is_set() else 1


# ---------------------------------------------------------------------------- #
# selftest / models / doctor / report / kb
# ---------------------------------------------------------------------------- #
def cmd_selftest(args, cfg, plugins, kb) -> int:  # noqa: ARG001
    from .selftest import run_selftest
    return run_selftest()


def cmd_models(args, cfg, plugins, kb) -> int:  # noqa: ARG001
    router = Router(cfg, extra_provider_types=plugins.provider_types)
    if not router.provider_ids():
        print("no providers configured - see examples/config.example.json")
        return 1
    print(f"{'provider':20} {'backend':38} role")
    roles = {}
    for role in ("supervisor", "strategist", "executor", "reflector"):
        try:
            roles[role] = router.backend_for(role).describe()
        except Exception as exc:  # noqa: BLE001
            roles[role] = f"({exc})"[:60]
    for pid in router.provider_ids():
        try:
            backend = router._build(pid)  # noqa: SLF001 - CLI display
            describe = backend.describe()
        except Exception as exc:  # noqa: BLE001
            describe = f"error: {exc}"[:60]
        used_by = ", ".join(r for r, d in roles.items() if d == describe) or "-"
        print(f"{pid:20} {describe:38} {used_by}")
    if args.ping:
        print("\npinging providers ...")
        for row in router.ping_all():
            state = f"ok {row['ms']:>8.1f} ms" if row["ok"] else f"FAIL {row['error'][:50]}"
            print(f"{row['provider']:20} {state}")
    return 0


def cmd_doctor(args, cfg, plugins, kb) -> int:  # noqa: ARG001
    from .core.challenge import detect_tools
    import platform
    print(f"ctf-harness {__version__} | python {sys.version.split()[0]} | {platform.system()}")
    avail = detect_tools(refresh=True)
    installed = sorted(k for k, ok in avail.items() if ok)
    missing = sorted(k for k, ok in avail.items()
                     if not ok and k in {"gdb", "radare2", "checksec", "binwalk",
                                         "sqlmap", "nmap", "sage", "steghide",
                                         "zsteg", "exiftool", "tshark", "hashcat",
                                         "upx", "py:pwn", "py:z3", "py:sympy"})
    print(f"installed tools: {', '.join(installed) or '(none)'}")
    print(f"missing (optional): {', '.join(missing) or '(none)'}")
    recipes = all_recipes(plugins.recipes)
    print(f"recipes: {len(recipes)} built-in + {len(plugins.recipes)} user/plugin")
    if plugins.loaded:
        print(f"plugins loaded: {', '.join(plugins.loaded)}")
    if plugins.errors:
        print(f"plugin errors: {plugins.errors}")
    if kb is not None:
        print(f"knowledge base: {kb.stats()}")
    else:
        print("knowledge base: not loaded")
    router = Router(cfg, extra_provider_types=plugins.provider_types)
    if router.provider_ids():
        print(f"providers configured: {', '.join(router.provider_ids())}")
        if getattr(args, "ping", False):
            for row in router.ping_all():
                state = f"ok {row['ms']:>8.1f} ms" if row["ok"] else f"FAIL {row['error'][:60]}"
                print(f"  {row['provider']:20} {state}")
    else:
        print("providers: NONE - L0/L1 still work, add one for L2/L3")
    return 0


def cmd_report(args, cfg, plugins, kb) -> int:  # noqa: ARG001
    from .report.writer import write_writeup
    session = Path(args.session)
    if not session.is_file():
        print(f"error: {session} not found")
        return 2
    out = write_writeup(session, Path(args.out), {"challenge": session.parent.parent.name})
    print(f"writeup written to {out}")
    return 0


def cmd_kb(args, cfg, plugins, kb) -> int:  # noqa: ARG001
    if kb is None:
        print("knowledge base empty - drop *.md/*.txt files into ./kb or ~/.ctfh/kb")
        return 1
    if args.query:
        print(kb.search(args.query))
    else:
        print(kb.stats())
        print("drop writeups/cheatsheets (*.md, *.txt) into ./kb or ~/.ctfh/kb")
    return 0


# ---------------------------------------------------------------------------- #
# entry point
# ---------------------------------------------------------------------------- #
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="ctfh",
        description="Speed-first, category-aware, multi-model AI harness for CTF")
    parser.add_argument("--version", action="version", version=f"ctfh {__version__}")
    parser.add_argument("--config", help="path to ctfh.json (default: search)")
    sub = parser.add_subparsers(dest="cmd")

    p_solve = sub.add_parser("solve", help="solve one challenge")
    p_solve.add_argument("path", nargs="?", help="challenge files directory")
    p_solve.add_argument("--name", help="challenge name")
    p_solve.add_argument("--category", help="web|pwn|crypto|reverse|forensics|misc")
    p_solve.add_argument("--url", help="web target URL")
    p_solve.add_argument("--remote", help="host:port (pwn)")
    p_solve.add_argument("--scorer", help="flag verifier URL (POST {\"flag\": ...})")
    p_solve.add_argument("--flag-format", help="regex for the flag (default flag{...})")
    p_solve.add_argument("--allow-host", action="append", default=[],
                         help="extra host in scope (repeatable)")
    p_solve.add_argument("--mode", choices=["supervisor", "single", "race"],
                         help="L2 strategy (default from config: supervisor)")
    p_solve.add_argument("--lanes", type=int, help="parallel lanes in race mode")
    p_solve.add_argument("--max-steps", type=int)
    p_solve.add_argument("--time-budget", type=float, help="seconds per challenge")
    p_solve.add_argument("--no-llm", action="store_true", help="L0/L1 only")
    p_solve.add_argument("--no-fast", action="store_true", help="skip L0")
    p_solve.add_argument("--interactive", action="store_true", help="enable ask_human")
    p_solve.add_argument("--json", action="store_true", help="also print JSON result")
    p_solve.add_argument("--run-dir", help="workspace directory for this solve")

    p_rush = sub.add_parser("rush", help="solve a whole competition in parallel")
    p_rush.add_argument("--ctfd", help="CTFd base URL")
    p_rush.add_argument("--token", help="CTFd API token")
    p_rush.add_argument("--dir", help="local directory with one folder per challenge")
    p_rush.add_argument("--workers", type=int, default=3)
    p_rush.add_argument("--time-budget", type=float, default=480)
    p_rush.add_argument("--submit", action="store_true",
                        help="auto-submit solved flags to CTFd")
    p_rush.add_argument("--mode", choices=["supervisor", "single", "race"])
    p_rush.add_argument("--order", choices=["points", "easiest", "name"],
                        default="points")
    p_rush.add_argument("--run-root", default="ctfh-runs")

    sub.add_parser("selftest", help="offline end-to-end test (no API keys)")

    p_models = sub.add_parser("models", help="list configured providers/roles")
    p_models.add_argument("--ping", action="store_true", help="measure latency")

    p_doctor = sub.add_parser("doctor", help="environment checkup")
    p_doctor.add_argument("--ping", action="store_true")

    p_report = sub.add_parser("report", help="regenerate a writeup from session.jsonl")
    p_report.add_argument("session", help="path to session.jsonl")
    p_report.add_argument("-o", "--out", default="writeup.md")

    p_kb = sub.add_parser("kb", help="knowledge base info / search")
    p_kb.add_argument("query", nargs="?", help="search query")

    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 0

    cfg = load_config(getattr(args, "config", None))
    plugins = load_plugins(cfg)
    kb = KnowledgeBase.load(default_kb_dirs())

    handlers = {"solve": cmd_solve, "rush": cmd_rush, "selftest": cmd_selftest,
                "models": cmd_models, "doctor": cmd_doctor,
                "report": cmd_report, "kb": cmd_kb}
    try:
        return handlers[args.cmd](args, cfg, plugins, kb)
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
