# Contributing

Thanks for helping! Keep the speed-first philosophy: zero required
dependencies for the core, deterministic offline tests, and cheap-before-
expensive stages.

## Dev setup

```bash
git clone <fork> && cd ctf-harness
python -m unittest discover -s tests   # must pass: 78 tests, offline
python -m ctf_harness selftest         # must print ALL PASS
```

No install needed for development; run everything from the repo root.
Python >= 3.10, stdlib only for the core package.

## Where to contribute

* **New recipes** (`ctf_harness/solver/recipes/`): must be deterministic,
  bounded (respect the recipe budget), and useful across many challenges.
  Add a matching test (see `test_solver.py` for the pattern).
* **Playbook improvements** (`ctf_harness/categories/`): methodology text
  must stay accurate — technique claims get checked in review.
* **Providers** (`ctf_harness/llm/providers/`): stdlib-only HTTP, retries,
  and a mock-backed test against a fake server (see `test_llm.py`).
* **Docs**: bilingual (EN primary + zh-CN mirror) — keep both in sync.

## Style

* Python 3.10+ typing, `from __future__ import annotations` at module top.
* No external dependencies in the core package. Optional integrations must
  degrade gracefully when the tool is missing.
* Every new tool: docs string + `args_help` JSON hint + tests.
* Every new recipe: an id, a test, an entry in `docs/RECIPES.md`.

## Commit / PR

Small focused PRs. Title format: `[recipes] padding-oracle probe`,
`[llm] x-provider`, `[docs] ...`. CI runs the full suite on Linux + Windows
for Python 3.10-3.12 — keep it green.

> AI生成
