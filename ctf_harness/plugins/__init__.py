"""Plugin system: drop-in extensions without forking the harness.

A plugin is a ``*.py`` file inside one of the plugin directories
(``./plugins``, ``./ctfh_plugins``, ``~/.ctfh/plugins``, plus any
``plugins.paths`` from ``ctfh.json``). It must define::

    def register(reg):
        reg.register_tool(MyTool())          # custom tool for the agent
        reg.register_recipe(MyRecipe(...))   # L1 recipe
        reg.register_provider("myllm", MyBackend)  # custom LLM backend type
        reg.on("flag_found", my_callback)   # event hook

Declarative JSON recipe packs in ``recipes.d/`` directories are loaded as
recipes too (see :mod:`ctf_harness.solver.declarative`).

Events: ``solve_start``, ``flag_found`` (payload: dict with challenge/flag/via),
``flag_rejected``, ``solve_end``.

WARNING: plugins are arbitrary Python code and run with your user privileges -
only install plugins you trust (same trust model as pytest/conda plugins).
"""

from __future__ import annotations

import importlib.util
import threading
from dataclasses import dataclass, field
from pathlib import Path

from ..solver.declarative import load_declarative_recipes

HOOK_EVENTS = ("solve_start", "flag_found", "flag_rejected", "solve_end")


@dataclass
class PluginRegistry:
    tools: list = field(default_factory=list)
    recipes: list = field(default_factory=list)
    provider_types: dict = field(default_factory=dict)
    hooks: dict = field(default_factory=dict)
    loaded: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ---------------------------------------------------------------- register
    def register_tool(self, tool) -> None:
        self.tools.append(tool)

    def register_recipe(self, recipe) -> None:
        self.recipes.append(recipe)

    def register_provider(self, name: str, cls) -> None:
        self.provider_types[str(name)] = cls

    def on(self, event: str, callback) -> None:
        self.hooks.setdefault(event, []).append(callback)

    # ------------------------------------------------------------------- fire
    def fire(self, event: str, payload=None) -> list[str]:
        errors: list[str] = []
        for callback in self.hooks.get(event, []):
            try:
                callback(payload)
            except Exception as exc:  # noqa: BLE001 - hooks must not break solving
                errors.append(f"{type(exc).__name__}: {exc}")
        if errors:
            self.errors.extend(f"hook {event}: {e}" for e in errors)
        return errors


def plugin_dirs(cfg: dict) -> list[Path]:
    dirs: list[Path] = []
    for extra in (cfg.get("plugins", {}) or {}).get("paths") or []:
        dirs.append(Path(extra))
    dirs.extend([Path.cwd() / "plugins",
                 Path.cwd() / "ctfh_plugins",
                 Path.home() / ".ctfh" / "plugins"])
    return dirs


def recipe_dirs(cfg: dict) -> list[Path]:
    custom = [Path(p) for p in (cfg.get("recipes", {}) or {}).get("paths") or []]
    return custom + [Path.cwd() / "recipes.d", Path.home() / ".ctfh" / "recipes.d"]


def load_plugins(cfg: dict) -> PluginRegistry:
    """Discover and load every plugin + declarative recipe pack."""
    registry = PluginRegistry()
    seen: set[Path] = set()
    for directory in plugin_dirs(cfg):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.py")):
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            _load_python_plugin(path, registry)
    declarative, errors = load_declarative_recipes(recipe_dirs(cfg))
    registry.recipes.extend(declarative)
    registry.errors.extend(errors)
    return registry


def _load_python_plugin(path: Path, registry: PluginRegistry) -> None:
    module_name = f"ctfh_plugin_{path.stem}"
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ImportError("cannot create import spec")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        register = getattr(module, "register", None) or getattr(module, "register_plugin", None)
        if register is None:
            registry.errors.append(f"{path.name}: no register(reg) function found")
            return
        register(registry)
        registry.loaded.append(path.name)
    except Exception as exc:  # noqa: BLE001 - a broken plugin must not kill the app
        registry.errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
