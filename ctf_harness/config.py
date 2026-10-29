"""Configuration loading (JSON, zero dependencies).

Lookup order (later wins): built-in defaults -> ``~/.ctfh.json`` -> ``./ctfh.json``
-> ``--config <file>`` -> environment variables (``CTFH_*_PROVIDER/_MODEL``).

Secrets can be referenced as ``"env:VARNAME"`` anywhere an ``api_key`` is
expected, so keys never need to live inside the config file.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

DEFAULT_CONFIG: dict = {
    "providers": {},  # name -> {type, base_url, api_key, model, timeout, options}
    "roles": {
        # each role: {"provider": <name>, "model": optional override,
        #             "fallback": [{"provider": ...}, ...]}
        "strategist": {},
        "executor": {},
        "reflector": {},
        "supervisor": {},   # falls back to strategist -> executor
    },
    "solve": {
        "max_steps": 24,            # executor steps per lane
        "time_budget_s": 600,       # wall clock per challenge
        "fast": True,               # run L0 heuristics first
        "fast_budget_s": 20,        # L0 deadline
        "recipe_budget_s": 90,      # L1 deadline
        "mode": "supervisor",       # supervisor | single | race
        "lanes": 2,                 # parallel hypotheses in race mode
        "supervisor_rounds": 3,     # dispatch rounds in supervisor mode
        "subagent_steps": 10,       # step budget per sub-agent task
        "subagents_parallel": 3,    # parallel specialists per round
        "race_models": [],          # [{"provider": "...", "model": "..."}, ...]
        "reflect_interval": 6,      # force strategy review every N steps
        "max_output_chars": 20000,  # observation truncation
        "shell_timeout_s": 60,
        "python_timeout_s": 120,
        "retry_reflect": True,      # one L3 replan round if L2 fails
    },
    "ctfd": {
        "base_url": None,
        "token": None,
        "cookie": None,
        "submit": False,
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge ``override`` into ``base`` (returns a new dict)."""
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def resolve_secret(value):
    """Resolve ``env:VARNAME`` references; other values pass through."""
    if isinstance(value, str) and value.startswith("env:"):
        return os.environ.get(value[4:], "")
    return value


def _apply_env_role_overrides(cfg: dict) -> None:
    for role in ("strategist", "executor", "reflector", "supervisor"):
        provider = os.environ.get(f"CTFH_{role.upper()}_PROVIDER")
        model = os.environ.get(f"CTFH_{role.upper()}_MODEL")
        if provider or model:
            entry = cfg.setdefault("roles", {}).setdefault(role, {})
            if provider:
                entry["provider"] = provider
            if model:
                entry["model"] = model


def load_config(path: str | os.PathLike | None = None) -> dict:
    """Load the effective configuration."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    else:
        candidates.append(Path.home() / ".ctfh.json")
        candidates.append(Path.cwd() / "ctfh.json")
    for cand in candidates:
        try:
            if cand.is_file():
                cfg = deep_merge(cfg, json.loads(cand.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read config {cand}: {exc}") from exc
    _apply_env_role_overrides(cfg)
    for prov in cfg.get("providers", {}).values():
        if isinstance(prov, dict):
            prov["api_key"] = resolve_secret(prov.get("api_key", ""))
    ctfd = cfg.get("ctfd", {})
    ctfd["token"] = resolve_secret(ctfd.get("token"))
    return cfg
