"""Orchestrator: the speed-first solve pipeline.

    L0  fast_scan heuristics        (zero tokens, sub-second)
    L1  recipe library + user packs (zero tokens, seconds)
    L2  strategist -> parallel race lanes (LLM + tools, first flag wins)
    L3  reflector replan retry      (strong model, only if L2 failed)

Everything is observable: full replay in ``.ctfh/session.jsonl``, human
writeup in ``writeup.md``, plugin hooks + webhook notifications on flags.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Callable

from .. import notify as notify_mod
from ..llm import LLMError, Message, Router
from ..plugins import PluginRegistry
from ..safety import Guard
from ..solver.heuristics import fast_scan
from ..solver.recipes import all_recipes
from ..solver.recipes.base import RecipeContext, run_recipes
from ..tools import ToolContext, build_registry
from .blackboard import Blackboard
from .challenge import Challenge
from .lanes import LaneOptions, LaneRunner, ResultBoard, run_lanes
from .session import SessionLog

STRATEGIST_SYSTEM = """You are the strategist of an AI CTF team. Given challenge
recon data, produce DISTINCT, testable attack hypotheses ranked by
(value / effort). Prefer classic high-yield archetypes for the category before
exotic ones. Output STRICT JSON in a fenced block:

```json
{"hypotheses": [{"title": "short name", "plan": "first 1-3 concrete tool actions"}, ...]}
```

No prose outside the JSON block."""


@dataclass
class SolveOptions:
    max_steps: int = 24
    time_budget_s: float = 600.0
    fast: bool = True
    fast_budget_s: float = 20.0
    recipe_budget_s: float = 90.0
    mode: str = "supervisor"        # supervisor | single | race
    lanes: int = 2
    supervisor_rounds: int = 3
    subagent_steps: int = 10
    subagents_parallel: int = 3
    reflect_interval: int = 6
    max_output_chars: int = 20000
    shell_timeout_s: float = 60.0
    python_timeout_s: float = 120.0
    retry_reflect: bool = True
    use_llm: bool = True
    interactive: bool = False

    @classmethod
    def from_config(cls, cfg: dict, **overrides) -> "SolveOptions":
        merged = dict(cfg.get("solve") or {})
        merged.update({k: v for k, v in overrides.items() if v is not None})
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in merged.items() if k in known})


@dataclass
class SolveResult:
    name: str
    status: str  # solved | unsolved | timeout
    flag: str | None = None
    via: str = ""
    lane: str = ""
    duration_s: float = 0.0
    recipes_executed: list = field(default_factory=list)
    lanes: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    session_path: str = ""
    writeup_path: str = ""
    usage: dict = field(default_factory=dict)
    error: str = ""

    @property
    def solved(self) -> bool:
        return self.status == "solved"


def make_verifier(challenge: Challenge, session: SessionLog) -> Callable[[str], tuple[bool, str]]:
    """Build the flag verifier: scorer endpoint if given, else format check."""

    def verify(flag: str) -> tuple[bool, str]:
        if challenge.scorer:
            try:
                body = json.dumps({"flag": flag}).encode("utf-8")
                request = urllib.request.Request(
                    challenge.scorer, data=body,
                    headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(request, timeout=15) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                correct = (
                    bool(data.get("correct"))
                    or str(data.get("status", "")).lower() == "correct"
                    or str(data.get("message", "")).lower().startswith("correct"))
                session.log("scorer", {"flag": flag[:80], "response": str(data)[:200]})
                return bool(correct), "verified by scorer endpoint"
            except Exception as exc:  # noqa: BLE001
                return False, f"scorer unreachable: {exc}"
        try:
            if re.search(challenge.flag_format, flag):
                return True, "matches declared flag format"
        except re.error:
            pass
        return False, "does not match the declared flag format"

    return verify


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", name).strip("_")
    return (slug or "challenge")[:60]


class Orchestrator:
    def __init__(self, cfg: dict, *, router: Router | None = None,
                 plugins: PluginRegistry | None = None, kb=None,
                 run_root: Path | None = None, out=print):
        self.cfg = cfg
        self.plugins = plugins if plugins is not None else PluginRegistry()
        self.registry = build_registry(interactive=False,
                                       extra_tools=self.plugins.tools)
        self.router = router or Router(cfg,
                                       extra_provider_types=self.plugins.provider_types)
        self.recipes = all_recipes(self.plugins.recipes)
        self.kb = kb
        self.run_root = Path(run_root) if run_root else Path.cwd() / "ctfh-runs"
        self.out = out

    # ------------------------------------------------------------------ solve
    def solve(self, challenge: Challenge, opts: SolveOptions | None = None,
              run_dir: Path | None = None) -> SolveResult:
        opts = opts or SolveOptions.from_config(self.cfg)
        started = time.monotonic()
        deadline = started + opts.time_budget_s
        run_dir = Path(run_dir) if run_dir else self.run_root / _slug(challenge.name)
        run_dir.mkdir(parents=True, exist_ok=True)

        session = SessionLog(
            run_dir / ".ctfh" / "session.jsonl",
            meta={"challenge": challenge.name, "category": challenge.category,
                  "url": challenge.url, "remote": challenge.remote,
                  "scorer": challenge.scorer})
        board = ResultBoard()
        verify = make_verifier(challenge, session)
        blackboard = Blackboard()
        result = SolveResult(name=challenge.name, status="unsolved",
                             session_path=str(run_dir / ".ctfh" / "session.jsonl"))
        self.plugins.fire("solve_start", {"name": challenge.name})
        try:
            self._run_pipeline(challenge, opts, run_dir, session, board, verify,
                               blackboard, result, started, deadline)
        except Exception as exc:  # noqa: BLE001 - surface, then finalize
            result.error = f"{type(exc).__name__}: {exc}"[:400]
            session.log("orchestrator_error", {"error": result.error})
        self._finalize(result, challenge, session, run_dir, started)
        return result

    # --------------------------------------------------------------- pipeline
    def _run_pipeline(self, challenge, opts, run_dir, session, board, verify,
                      blackboard, result, started, deadline) -> None:
        # ---------------- L0: zero-thought heuristics ---------------------- #
        if opts.fast and challenge.path and Path(challenge.path).exists():
            budget = min(opts.fast_budget_s, max(1.0, deadline - time.monotonic()))
            findings = fast_scan(challenge.path, challenge.flag_format, budget_s=budget)
            session.log("l0_scan", {"findings": [f"{f.flag} via {f.via}"
                                                for f in findings][:10]})
            for finding in findings:
                ok, message = board.propose(finding.flag, f"L0/{finding.via}", verify)
                if ok:
                    result.via, result.lane = finding.via, "L0"
                    self._mark_solved(result, board, session, started)
                    return
                blackboard.add(f"L0 rejected: {finding.flag} ({finding.via})", "l0")

        # ---------------- L1: recipe library -------------------------------- #
        if not board.solved_event.is_set() and time.monotonic() < deadline:
            guard = Guard(run_dir, scope_hosts=challenge.scope_hosts())
            l1_ctx = ToolContext(
                workspace=run_dir, guard=guard, challenge=challenge, session=session,
                blackboard=blackboard,
                propose_flag=lambda flag: board.propose(flag, "L1", verify),
                step_dir=run_dir / ".ctfh" / "l1",
                max_output_chars=opts.max_output_chars,
                shell_timeout_s=opts.shell_timeout_s,
                python_timeout_s=opts.python_timeout_s, lane="l1")
            recipe_ctx = RecipeContext(challenge=challenge, guard=guard,
                                       registry=self.registry, tool_ctx=l1_ctx,
                                       flag_re=challenge.flag_format)
            budget = min(opts.recipe_budget_s, max(2.0, deadline - time.monotonic()))
            findings, executed = run_recipes(recipe_ctx, self.recipes,
                                             budget_s=budget)
            result.recipes_executed = executed
            session.log("l1_recipes", {"executed": executed})
            for finding in findings:
                ok, message = board.propose(finding.flag, f"L1/{finding.via}", verify)
                if ok:
                    result.via, result.lane = finding.via, "L1"
                    self._mark_solved(result, board, session, started)
                    return

        # ---------------- L2: supervisor (default) or race lanes ----------- #
        if opts.use_llm and not board.solved_event.is_set() \
                and time.monotonic() < deadline - 5:
            from ..categories import select as select_playbook
            playbook = select_playbook(challenge)
            session.log("playbook", {"id": playbook.id, "title": playbook.title})
            kb_snippet = ""
            if self.kb is not None:
                kb_snippet = self.kb.search(
                    f"{challenge.name}\n{challenge.category or ''}\n"
                    f"{challenge.description}\n{challenge.recon_summary()}")
                if kb_snippet:
                    session.log("kb_hits", {"chars": len(kb_snippet)})
            backends = self.router.race_backends()
            if not backends:
                session.log("l2_skip", {"reason": "no LLM provider configured"})
            else:
                lane_opts = LaneOptions(
                    max_steps=opts.max_steps,
                    reflect_interval=opts.reflect_interval,
                    max_output_chars=opts.max_output_chars,
                    shell_timeout_s=opts.shell_timeout_s,
                    python_timeout_s=opts.python_timeout_s,
                    interactive=opts.interactive)
                if opts.mode == "supervisor":
                    from .supervisor import SupervisorAgent
                    supervisor = SupervisorAgent(router=self.router,
                                                 registry=self.registry,
                                                 session=session, out=self.out)
                    reports = supervisor.run(
                        challenge=challenge, playbook=playbook, board=board,
                        verify=verify, blackboard=blackboard, run_dir=run_dir,
                        deadline=deadline, opts=opts, kb_snippet=kb_snippet)
                    result.lanes = reports
                    session.log("supervisor_done",
                                {"reports": [r.summary_line() for r in reports]})
                else:
                    lane_count = max(1, opts.lanes) if opts.mode == "race" else 1
                    hypotheses = self._strategize(challenge, playbook, count=lane_count)
                    if not hypotheses:
                        hypotheses = playbook.seed_hypotheses(challenge)[:lane_count] \
                            or ["Apply the category playbook from the top."]
                    result.lanes = self._run_lane_batch(
                        challenge, playbook, hypotheses[:lane_count], backends,
                        board, verify, blackboard, session, run_dir, lane_opts,
                        opts, deadline, kb_snippet)

                if board.solved_event.is_set():
                    result.via = f"L2/{board.winner_lane}"
                    result.lane = board.winner_lane or ""
                    self._mark_solved(result, board, session, started)
                    return

                # ------------- L3: reflector replan, one retry ------------- #
                if opts.retry_reflect and time.monotonic() < deadline - 30:
                    advice = self._final_reflection(challenge, playbook,
                                                    blackboard, result.lanes)
                    if advice:
                        session.log("l3_retry", {"advice": advice[:1500]})
                        retry = self._run_lane_batch(
                            challenge, playbook, [advice], backends[:1],
                            board, verify, blackboard, session, run_dir,
                            lane_opts, opts, deadline, "", lane_id="reflect")
                        result.lanes.extend(retry)
                        if board.solved_event.is_set():
                            result.via = f"L3/{board.winner_lane}"
                            result.lane = board.winner_lane or ""
                            self._mark_solved(result, board, session, started)
                            return

        if time.monotonic() >= deadline:
            result.status = "timeout"

    # ------------------------------------------------------------- lane batch
    def _run_lane_batch(self, challenge, playbook, hypotheses, backends, board,
                        verify, blackboard, session, run_dir, lane_opts, opts,
                        deadline, kb_snippet, lane_id=None):
        lanes_root = run_dir / ".ctfh" / "lanes"
        seed_notes = blackboard.items()
        runners: list[LaneRunner] = []
        for index, hypothesis in enumerate(hypotheses):
            backend = backends[index % len(backends)]
            lane_name = lane_id if lane_id else f"lane{index + 1}"
            runners.append(LaneRunner(
                lane_id=lane_name, hypothesis=hypothesis, challenge=challenge,
                playbook=playbook, backend=backend, router=self.router,
                session=session, board=board, registry=self.registry,
                lane_root=lanes_root / lane_name, opts=lane_opts,
                seed_notes=seed_notes,
                kb_snippet=kb_snippet if index == 0 else "",
                verify_flag=verify))
        return run_lanes(runners, deadline, session)

    # -------------------------------------------------------------- strategist
    def _strategize(self, challenge, playbook, count: int) -> list[str]:
        try:
            prompt = (
                f"RECON:\n{challenge.recon_summary()}\n\n"
                f"CATEGORY PLAYBOOK: {playbook.title}\n"
                f"Produce up to {count} distinct attack hypotheses ranked by "
                f"(likelihood * value) / effort.")
            text = self.router.chat_role(
                "strategist",
                [Message("system", STRATEGIST_SYSTEM), Message("user", prompt)],
                max_tokens=1200, temperature=0.3)
        except LLMError as exc:
            return []
        for match in re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL):
            try:
                data = json.loads(match)
            except json.JSONDecodeError:
                continue
            out: list[str] = []
            for item in (data.get("hypotheses") or [])[:count]:
                if not isinstance(item, dict):
                    continue
                title = str(item.get("title", "")).strip()
                plan = str(item.get("plan", "")).strip()
                combined = f"{title}: {plan}" if plan else title
                if combined:
                    out.append(combined)
            if out:
                return out
        lines = [re.sub(r"^\s*(?:\d+[\.\):]|[-*])\s*", "", line).strip()
                 for line in text.splitlines()
                 if re.match(r"\s*(?:\d+[\.\):]|[-*])\s+\S", line)]
        return [line for line in lines if len(line) > 10][:count]

    def _final_reflection(self, challenge, playbook, blackboard, lanes) -> str:
        def lane_line(entry) -> str:
            lane_id = getattr(entry, "lane_id", "?")
            steps = getattr(entry, "steps", 0)
            stuck = getattr(entry, "stuck_count", 0)
            status = getattr(entry, "status", "")
            error = getattr(entry, "last_error", "") or getattr(entry, "error", "")
            conclusion = getattr(entry, "conclusion", "")
            bits = f"- {lane_id} ({steps} steps"
            if stuck:
                bits += f", stuck={stuck}"
            if status:
                bits += f", status={status}"
            bits += f"): {error or conclusion[:200] or '-'}"
            return bits

        lanes_text = "\n".join(lane_line(entry) for entry in (lanes or []))
        prompt = (
            f"CHALLENGE RECON:\n{challenge.recon_summary()}\n\n"
            f"PLAYBOOK: {playbook.title}\n\n"
            f"NOTES:\n{blackboard.render(40) or '(none)'}\n\n"
            f"FAILED LANES:\n{lanes_text}\n\n"
            "All lanes failed. Produce ONE decisive new plan: the most likely "
            "overlooked angle, with concrete first tool calls.")
        try:
            return self.router.chat_role(
                "reflector",
                [Message("system", "You are the lead CTF player doing a final "
                                  "replan after failures. Be concrete and terse."),
                 Message("user", prompt)],
                max_tokens=1024, temperature=0.4)
        except LLMError:
            return ""

    # ---------------------------------------------------------------- finish
    def _mark_solved(self, result: SolveResult, board: ResultBoard,
                     session: SessionLog, started: float) -> None:
        result.status = "solved"
        result.flag = board.flag
        session.log("flag_found", {"flag": board.flag, "via": result.via,
                                   "lane": result.lane})
        payload = {"name": result.name, "flag": board.flag,
                   "via": result.via, "lane": result.lane}
        self.plugins.fire("flag_found", payload)
        errors = notify_mod.notify(self.cfg, "flag_found", payload)
        if errors:
            session.log("notify_error", {"errors": errors})

    def _finalize(self, result: SolveResult, challenge: Challenge,
                  session: SessionLog, run_dir: Path, started: float) -> None:
        result.duration_s = round(time.monotonic() - started, 1)
        result.usage = self.router.usage.as_dict()
        try:
            from ..report.writer import write_writeup
            writeup = run_dir / "writeup.md"
            write_writeup(session.path, writeup, {
                "challenge": challenge.name,
                "category": challenge.category or "auto",
                "url": challenge.url or "",
                "remote": challenge.remote or "",
                "status": result.status,
                "flag": result.flag or "",
                "via": result.via,
                "duration_s": result.duration_s,
            })
            result.writeup_path = str(writeup)
        except Exception as exc:  # noqa: BLE001 - reporting must not break solve
            session.log("report_error", {"error": str(exc)[:200]})
        session.log("result", {"status": result.status, "flag": result.flag,
                               "duration_s": result.duration_s})
        self.plugins.fire("solve_end", {"name": result.name,
                                         "status": result.status,
                                         "flag": result.flag})
