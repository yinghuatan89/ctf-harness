"""Supervisor agent: plan -> dispatch specialists in parallel -> integrate.

The supervisor never touches tools. Each round it:
  1. reviews recon + blackboard + previous (already distilled) reports,
  2. emits 1..3 INDEPENDENT subtasks as JSON,
  3. runs them as parallel ``SpecialistRunner`` sub-agents,
  4. merges their reports into the team blackboard,
  5. repeats until the flag is found, the budget is spent, or it says stop.

Efficiency guarantees:
* context quarantine - messy exploration never enters the supervisor prompt,
* dynamic round budgets - remaining time is split across remaining rounds,
* early global stop - any sub-agent flag win cancels every other branch,
* finisher dispatch - when a report says the flag is one step away, the
  supervisor sends a single focused subtask to grab it.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import replace
from pathlib import Path

from ..llm import LLMError, Message, Router
from .lanes import LaneOptions, run_lanes
from .subagent import SPECIALIST_ROLES, SpecialistRunner, TaskReport

SUPERVISOR_SYSTEM = """You are the SUPERVISOR of an AI CTF team. You never run
tools yourself; you decompose, dispatch and integrate. You receive the
challenge recon, the team blackboard and DISTILLED sub-agent reports.

Each round, output STRICT JSON in one fenced block:

```json
{"analysis": "one line", "verdict": "continue|stop",
 "subtasks": [{"id": "t1",
   "role": "recon|decompiler|exploit_dev|web_fuzzer|crypto_analyst|forensics_analyst|generalist",
   "brief": "self-contained concrete instruction", "steps": 8}]}
```

Rules:
- 1 to 3 subtasks per round, they MUST be independent (no subtask needs
  another subtask's result).
- briefs are concrete: which file/endpoint/parameter, what to produce.
- integrate past reports: never re-dispatch answered questions; go deeper.
- when a report shows the flag is one step away, dispatch ONE finisher
  subtask that performs exactly that step.
- verdict "stop" only when nothing plausible remains. JSON only, no prose."""


class SupervisorAgent:
    def __init__(self, *, router: Router, registry, session, out=print):
        self.router = router
        self.registry = registry
        self.session = session
        self.out = out

    # -------------------------------------------------------------------- run
    def run(self, *, challenge, playbook, board, verify, blackboard,
            run_dir: Path, deadline: float, opts, kb_snippet: str = "") \
            -> list[TaskReport]:
        reports: list[TaskReport] = []
        lane_opts = LaneOptions(
            max_steps=opts.subagent_steps,
            reflect_interval=max(3, opts.subagent_steps // 2),
            max_output_chars=opts.max_output_chars,
            shell_timeout_s=opts.shell_timeout_s,
            python_timeout_s=opts.python_timeout_s,
            interactive=opts.interactive)
        recon = challenge.recon_summary()
        rounds_left = max(1, opts.supervisor_rounds)
        backends = self.router.race_backends()

        while not board.solved_event.is_set() and rounds_left > 0:
            remaining = deadline - time.monotonic()
            if remaining < 25:
                break
            if not backends:
                self.session.log("supervisor_skip", {"reason": "no LLM provider"})
                break
            subtasks = self._plan(recon, blackboard, reports, rounds_left)
            if not subtasks:
                self.session.log("supervisor_stop", {"rounds_left": rounds_left})
                break
            per_round = max(60.0, remaining / max(1, rounds_left))
            round_deadline = min(deadline, time.monotonic() + per_round)
            self.session.log("supervisor_dispatch",
                             {"tasks": [t["id"] for t in subtasks],
                              "roles": [t["role"] for t in subtasks],
                              "budget_s": round(per_round, 1)})

            sub_root = run_dir / ".ctfh" / "sub"
            runners: list[SpecialistRunner] = []
            for index, task in enumerate(subtasks[:opts.subagents_parallel]):
                runners.append(SpecialistRunner(
                    lane_id=task["id"], role=task["role"], brief=task["brief"],
                    task_id=task["id"],
                    subagent_steps=min(task.get("steps") or opts.subagent_steps,
                                       opts.subagent_steps * 2),
                    hypothesis=task["brief"][:200], challenge=challenge,
                    playbook=playbook, backend=backends[index % len(backends)],
                    router=self.router, session=self.session, board=board,
                    registry=self.registry,
                    lane_root=sub_root / task["id"], opts=lane_opts,
                    seed_notes=blackboard.items(),
                    kb_snippet=kb_snippet if index == 0 else "",
                    verify_flag=verify))
            finished = run_lanes(runners, round_deadline, self.session)

            new_reports = [r for r in finished if isinstance(r, TaskReport)]
            if len(new_reports) < len(runners):
                for runner in runners:
                    if not any(r.lane_id == runner.lane_id for r in new_reports):
                        new_reports.append(TaskReport(
                            task_id=runner.task_id, role=runner.role,
                            brief=runner.brief[:200], status="timeout",
                            conclusion="sub-agent did not report in time",
                            lane_id=runner.lane_id))
            reports.extend(new_reports)
            for report in new_reports:
                line = f"[{report.task_id}/{report.role}] {report.status}: " \
                       f"{report.conclusion[:400]}"
                if report.next_step:
                    line += f" NEXT: {report.next_step[:200]}"
                blackboard.add(line, "subagent")
                self.out(f"  [supervisor] {report.summary_line()}")
            rounds_left -= 1
        return reports

    # ------------------------------------------------------------------- plan
    def _plan(self, recon: str, blackboard, reports: list[TaskReport],
              rounds_left: int) -> list[dict]:
        reports_text = "\n".join(
            f"- {r.task_id} ({r.role}, {r.status}): {r.conclusion[:300]}"
            + (f" [next: {r.next_step[:150]}]" if r.next_step else "")
            for r in reports[-8:]) or "(none yet - this is round 1)"
        user = (
            f"RECON:\n{recon}\n\n"
            f"BLACKBOARD:\n{blackboard.render(50) or '(empty)'}\n\n"
            f"SUB-AGENT REPORTS:\n{reports_text}\n\n"
            f"Rounds remaining: {rounds_left}. Emit this round's dispatch JSON.")
        try:
            text = self.router.chat_role(
                "supervisor",
                [Message("system", SUPERVISOR_SYSTEM), Message("user", user)],
                max_tokens=1200, temperature=0.25)
        except LLMError as exc:
            self.session.log("supervisor_plan_error", {"error": str(exc)[:200]})
            return []
        for match in re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL):
            try:
                data = json.loads(match)
            except json.JSONDecodeError:
                continue
            verdict = str(data.get("verdict", "continue")).lower()
            subtasks: list[dict] = []
            for item in (data.get("subtasks") or [])[:3]:
                if not isinstance(item, dict):
                    continue
                brief = str(item.get("brief", "")).strip()
                if len(brief) < 10:
                    continue
                role = str(item.get("role", "generalist")).lower()
                if role not in SPECIALIST_ROLES:
                    role = "generalist"
                steps = item.get("steps")
                subtasks.append({
                    "id": str(item.get("id") or f"t{len(subtasks) + 1}")[:16],
                    "role": role, "brief": brief[:1200],
                    "steps": int(steps) if isinstance(steps, (int, float)) and steps > 0
                    else None})
            if subtasks:
                return subtasks
            if verdict == "stop":
                return []
        # JSON missing/unparseable: keep the team moving with a generic dispatch
        return [{
            "id": "t_fallback", "role": "generalist",
            "brief": "Continue the category playbook from the top; prioritize "
                     "the highest-value angle not yet covered by the reports.",
            "steps": None}]
