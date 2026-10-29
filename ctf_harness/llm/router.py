"""Role router: maps strategist/executor/reflector roles to backends.

Features that matter during a live competition:
* one provider entry, many roles - a cheap fast local model can be the
  executor while a strong cloud model only gets used by the reflector;
* per-role fallback chains (``roles.executor.fallback``) - if the primary
  provider dies, the next one takes over automatically;
* a tiny circuit breaker: after 3 consecutive failures a backend is marked
  dead for 5 minutes instead of burning the clock;
* ``race_backends()``: the model line-up for L2 race lanes.
"""

from __future__ import annotations

import threading
import time

from .base import ChatBackend, LLMError, Message, UsageReport
from .providers import AnthropicBackend, MockBackend, OpenAICompatibleBackend

BUILTIN_PROVIDER_TYPES: dict[str, type] = {
    "openai_compatible": OpenAICompatibleBackend,
    "openai": OpenAICompatibleBackend,
    "anthropic": AnthropicBackend,
    "claude": AnthropicBackend,
    "mock": MockBackend,
}

ROLES = ("strategist", "executor", "reflector", "supervisor")
BREAKER_THRESHOLD = 3
BREAKER_COOLDOWN_S = 300.0


class Router:
    def __init__(self, cfg: dict, *, extra_provider_types: dict[str, type] | None = None):
        self.cfg = cfg
        self.provider_types = dict(BUILTIN_PROVIDER_TYPES)
        if extra_provider_types:
            self.provider_types.update(extra_provider_types)
        self.usage = UsageReport()
        self._cache: dict[tuple, ChatBackend] = {}
        self._cache_lock = threading.Lock()
        self._breaker: dict[str, tuple[int, float]] = {}
        self._breaker_lock = threading.Lock()

    # ------------------------------------------------------------- providers
    def provider_ids(self) -> list[str]:
        return sorted(self.cfg.get("providers", {}).keys())

    def _build(self, provider_id: str, model_override: str | None = None) -> ChatBackend:
        key = (provider_id, model_override)
        with self._cache_lock:
            if key in self._cache:
                return self._cache[key]
        spec = self.cfg.get("providers", {}).get(provider_id)
        if not isinstance(spec, dict):
            raise LLMError(f"provider '{provider_id}' is not configured")
        ptype = str(spec.get("type") or "openai_compatible").lower()
        cls = self.provider_types.get(ptype)
        if cls is None:
            raise LLMError(
                f"provider '{provider_id}' has unknown type '{ptype}'; "
                f"known: {', '.join(sorted(self.provider_types))}")
        kwargs = {k: v for k, v in spec.items() if k not in ("type", "enabled")}
        if model_override:
            kwargs["model"] = model_override
        try:
            backend = cls(**kwargs)
        except TypeError as exc:
            raise LLMError(f"provider '{provider_id}' has bad options: {exc}") from exc
        with self._cache_lock:
            self._cache[key] = backend
        return backend

    # ----------------------------------------------------------------- roles
    def _role_entry(self, role: str) -> dict:
        return self.cfg.get("roles", {}).get(role) or {}

    def _primary_provider_id(self, role: str) -> str | None:
        pid = self._role_entry(role).get("provider")
        if pid:
            return pid
        if role == "supervisor":
            for fallback_role in ("strategist", "executor"):
                pid = self._role_entry(fallback_role).get("provider")
                if pid:
                    return pid
        if role != "executor":
            pid = self._role_entry("executor").get("provider")
            if pid:
                return pid
        ids = self.provider_ids()
        return ids[0] if ids else None

    def backend_for(self, role: str) -> ChatBackend:
        pid = self._primary_provider_id(role)
        if not pid:
            raise LLMError(
                "no LLM provider configured. Create ctfh.json with a providers section "
                "(see examples/config.example.json) or run in --no-llm mode.")
        return self._build(pid, self._role_entry(role).get("model"))

    def _fallback_backends(self, role: str) -> list[ChatBackend]:
        out: list[ChatBackend] = []
        for item in self._role_entry(role).get("fallback") or []:
            if isinstance(item, dict):
                pid, model = item.get("provider"), item.get("model")
            else:
                pid, model = str(item), None
            try:
                out.append(self._build(pid, model))
            except LLMError:
                continue
        return out

    # ------------------------------------------------------------ chat calls
    def chat_role(self, role: str, messages: list[Message], **kwargs) -> str:
        """Chat with the primary backend for ``role``; fail over down the chain."""
        backends = [self.backend_for(role)] + self._fallback_backends(role)
        last_exc: LLMError | None = None
        for index, backend in enumerate(backends):
            if self._is_dead(backend):
                if index == len(backends) - 1:
                    raise LLMError(f"[{backend.describe()}] circuit breaker open (recent failures)")
                continue
            try:
                prompt_chars = sum(len(m.content) for m in messages)
                text = backend.chat(messages, **kwargs)
                self.usage.add(prompt_chars, len(text))
                self._record(backend, ok=True)
                return text
            except LLMError as exc:
                last_exc = exc
                self.usage.failed()
                self._record(backend, ok=False)
        if last_exc:
            raise last_exc
        raise LLMError(f"no live backend for role '{role}'")

    def race_backends(self) -> list[ChatBackend]:
        entries = self.cfg.get("solve", {}).get("race_models") or []
        if not entries:
            return [self.backend_for("executor")]
        out: list[ChatBackend] = []
        for item in entries:
            try:
                if isinstance(item, dict):
                    out.append(self._build(item["provider"], item.get("model")))
                else:
                    out.append(self._build(str(item)))
            except (LLMError, KeyError):
                continue
        return out or [self.backend_for("executor")]

    # --------------------------------------------------------- circuit break
    def _record(self, backend: ChatBackend, *, ok: bool) -> None:
        key = backend.describe()
        with self._breaker_lock:
            if ok:
                self._breaker.pop(key, None)
            else:
                fails, _ = self._breaker.get(key, (0, 0.0))
                fails += 1
                dead_until = time.monotonic() + BREAKER_COOLDOWN_S if fails >= BREAKER_THRESHOLD else 0.0
                self._breaker[key] = (fails, dead_until)

    def _is_dead(self, backend: ChatBackend) -> bool:
        with self._breaker_lock:
            entry = self._breaker.get(backend.describe())
        return bool(entry and entry[1] > time.monotonic())

    def breaker_status(self) -> dict[str, str]:
        now = time.monotonic()
        with self._breaker_lock:
            return {key: ("DEAD" if until > now else "ok") for key, (_, until) in self._breaker.items()}

    # ------------------------------------------------------------------ ping
    def ping_all(self, *, providers: list[str] | None = None) -> list[dict]:
        """Ping every configured provider in parallel; returns sorted rows."""
        ids = providers or self.provider_ids()
        rows: dict[str, dict] = {}
        threads = []

        def worker(pid: str) -> None:
            try:
                backend = self._build(pid)
            except LLMError as exc:
                rows[pid] = {"provider": pid, "describe": "-", "ok": False,
                             "ms": -1.0, "error": str(exc)[:120]}
                return
            ok, ms, err = backend.ping()
            with self._breaker_lock:
                self._record(backend, ok=ok)
            rows[pid] = {"provider": pid, "describe": backend.describe(), "ok": ok,
                         "ms": round(ms, 1), "error": err}

        for pid in ids:
            thread = threading.Thread(target=worker, args=(pid,), daemon=True)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join(timeout=45)
        return sorted(rows.values(), key=lambda r: (not r["ok"], r["ms"]))
