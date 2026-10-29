# Architecture

## Solve pipeline (per challenge)

```
Orchestrator.solve(challenge)
 │
 ├─ 0. recon          local-only: file inventory + magic sniffing, endpoints,
 │                     flag format, installed-tool detection (no network)
 ├─ 1. L0 heuristics  fast_scan() deterministic cascade, zero LLM tokens
 │                     plain regex → base64/32 (nested) → hex → gzip/zlib/
 │                     bz2/xz → zip(+tiny pw list)/tar → Caesar 1..25 →
 │                     single-byte XOR → known-key XOR
 │                     candidates verified via scorer/flag-format → done?
 ├─ 2. L1 recipes     19 built-in + user recipes (recipes.d + plugins),
 │                     zero LLM tokens; findings + blackboard notes
 ├─ 3. L2             mode=supervisor (default) or single|race lanes
 │                     supervisor rounds: plan JSON → parallel specialists
 │                     → TaskReports merged into the blackboard
 └─ 4. L3             reflector reviews all failures → one retry lane
       (only if L2 found nothing)
 every flag candidate → ResultBoard.propose() → verify (scorer endpoint
 or flag-format regex) → first accepted flag stops ALL branches.
```

## Modules

| Path | Role |
|---|---|
| `core/orchestrator.py` | pipeline, verifier, strategist/reflector prompts, finalize/report |
| `core/lanes.py` | `LaneRunner` (one autonomous agent+tools loop), `ResultBoard`, `run_lanes` |
| `core/supervisor.py` | supervisor dispatch rounds (plan → run specialists → integrate) |
| `core/subagent.py` | `SpecialistRunner` + role SOPs + `TaskReport` |
| `core/protocol.py` | fenced-JSON tool-call protocol (works with ANY text model) |
| `core/challenge.py` | challenge model, recon, scope parsing, tool detection |
| `llm/` | provider-agnostic backends + role router with fallback chains & breaker |
| `tools/` | shell / run_python / http / files / notes / submit_flag / declare_stuck / report / ask_human |
| `safety/guard.py` | workspace jail, shell deny-list, HTTP scope enforcement |
| `solver/` | L0 heuristics, flag extraction, RSA kit, recipes package |
| `solver/declarative.py` | user recipe DSL (JSON packs) |
| `categories/` | 6 playbooks + auto-detection |
| `ctfd/client.py` | CTFd API v1 client (rush mode) |
| `plugins/`, `kb.py`, `notify.py` | extension surface |
| `report/writer.py` | writeup.md from session.jsonl |

## Design decisions

**Why a text protocol instead of native function calling?** Local model
servers and smaller vendors implement function calling inconsistently. A
strict fenced-JSON block (`parse_tool_calls`) works with every text model,
is trivially repairable (malformed output → the model gets the parse error
back and re-emits), and is replayable in `session.jsonl`.

**Why context quarantine for sub-agents?** Solving a pwn binary burns tens
of thousands of tokens on decompiled junk. A specialist burns *its own*
window on that and returns a ≤150-word `report`; the supervisor prompt only
ever contains recon + distilled reports. This is the single biggest cost
control in multi-agent harnesses (the same reason coding agents use Task
sub-agents).

**Why lanes share one ResultBoard?** Any branch (L0, L1, lane, specialist)
that produces a *verified* flag sets a threading.Event; every loop checks it
at each step boundary, so wasted parallel work stops within seconds of a
win.

**Why recipes run before the LLM?** Classic archetypes (base64 blobs, SQLi
logins, RSA small-e, LSB steg, …) are deterministic. Scripted attacks cost
~0 and free the LLM budget for the challenges that actually need reasoning.

**Why verify against a scorer when available?** LLMs hallucinate flags.
With `--scorer` every candidate is POSTed once (deduplicated, capped at 10
unique attempts); without one, the declared flag-format regex is the
acceptance test.

**Why budgets everywhere?** Competitions are won on wall-clock. `time_budget_s`
per challenge, per-round budgets in supervisor mode, per-tool timeouts, per
lane step caps, and `run_lanes` never idles after all threads finish.

## Pattern credits

The supervisor/specialist split adapts publicly documented multi-agent
patterns (LangGraph-style supervisor dispatch, MetaGPT-style role SOPs,
coding-agent-style Task sub-agent context quarantine) to the CTF domain.
All code here is an original implementation; nothing is copied from those
projects.

> AI生成
