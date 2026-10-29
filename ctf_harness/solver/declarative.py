"""Declarative user recipes (自定义预案): a no-code JSON DSL.

Drop ``*.json`` files into ``recipes.d/`` (repo dir) or ``~/.ctfh/recipes.d/``
and they run in the L1 stage before any LLM tokens are spent.

Schema::

    {
      "id": "my.oracle_probe",
      "title": "Probe padding oracle on /api/check",
      "category": "web",                      // optional gate
      "requires": {"url": true, "content_regex": "padding"},  // optional
      "steps": [
        {"tool": "http", "args": {"method": "GET", "url": "{{url}}"},
         "capture": {"page": "<body>(.*?)</body>"}},
        {"tool": "run_python",
         "code": "print({{capture:page}})"},
        {"tool": "shell", "args": {"cmd": "echo {{challenge_name}}"}}
      ]
    }

Template variables available in ``args``/``code``/``cmd``:

* ``{{url}}`` ``{{remote}}`` ``{{flag_format}}`` - challenge fields
* ``{{name}}`` / ``{{challenge_name}}`` - challenge name
* ``{{file:<relative path>}}`` - file content (first 64KB) from the workspace
* ``{{capture:<name>}}`` - regex group captured from a previous step
* ``{{var:<name>}}`` - value stored earlier via a step's ``"set"`` key

Every step's output is scanned for the flag format automatically.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .recipes.base import Recipe

_FILE_RE = re.compile(r"\{\{file:([^}]+)\}\}")
_CAPTURE_RE = re.compile(r"\{\{capture:([A-Za-z0-9_]+)\}\}")
_VAR_RE = re.compile(r"\{\{var:([A-Za-z0-9_]+)\}\}")


class DeclarativeRecipe(Recipe):
    def __init__(self, spec: dict, source: str = ""):
        super().__init__(
            id=str(spec.get("id") or f"user.{source or 'recipe'}"),
            title=str(spec.get("title") or spec.get("id") or "user recipe"),
            categories=tuple(spec.get("categories") or
                             ((spec.get("category"),) if spec.get("category") else ())),
            description=str(spec.get("description") or ""))
        self.spec = spec
        self.source = source

    # ------------------------------------------------------------------ match
    def match(self, challenge) -> bool:
        requires = self.spec.get("requires") or {}
        if self.categories and challenge.category and challenge.category not in self.categories:
            return False
        if requires.get("url") and not challenge.url:
            return False
        if requires.get("remote") and not challenge.remote:
            return False
        content_regex = requires.get("content_regex")
        if content_regex:
            haystack = (challenge.description or "")
            for path in list(challenge.iter_files())[:10]:
                try:
                    haystack += path.read_bytes()[:64_000].decode("latin-1")
                except OSError:
                    continue
            if not re.search(content_regex, haystack, re.DOTALL):
                return False
        if requires.get("files"):
            for pattern in requires["files"]:
                if not any(re.search(pattern, p.name)
                           for p in list(challenge.iter_files())[:50]):
                    return False
        return True

    # -------------------------------------------------------------------- run
    def run(self, rc) -> list:
        state: dict[str, str] = {}
        outputs: list[str] = []
        for index, step in enumerate(self.spec.get("steps") or []):
            if index >= 12:
                break
            tool = str(step.get("tool") or "")
            template = step.get("args", step.get("code", step.get("cmd", "")))
            rendered = self._render(template, rc, state) if isinstance(template, str) else template
            args: dict = {}
            if tool == "shell":
                args = {"cmd": rendered}
            elif tool == "run_python":
                args = {"code": rendered}
            elif isinstance(rendered, dict):
                args = {k: self._render(v, rc, state) if isinstance(v, str) else v
                        for k, v in rendered.items()}
            elif isinstance(rendered, str):
                args = {"url": rendered, "method": str(step.get("method", "GET"))}
            result = rc.dispatch(tool, **args)
            output = result.output or ""
            outputs.append(output)
            for name, pattern in (step.get("capture") or {}).items():
                match = re.search(pattern, output, re.DOTALL)
                if match:
                    state[name] = match.group(1) if match.groups() else match.group(0)
            if step.get("set"):
                for name, value in step["set"].items():
                    state[name] = self._render(value, rc, state)
            found = rc.scan(output)
            if found:
                return found
        return rc.scan(*outputs)

    # ---------------------------------------------------------------- helpers
    def _render(self, template: str, rc, state: dict) -> str:
        ch = rc.challenge
        mapping = {
            "{{url}}": ch.url or "",
            "{{remote}}": ch.remote or "",
            "{{flag_format}}": ch.flag_format or "",
            "{{name}}": ch.name or "challenge",
            "{{challenge_name}}": ch.name or "challenge",
        }
        out = template
        for token, value in mapping.items():
            out = out.replace(token, str(value))
        out = _FILE_RE.sub(lambda m: self._file_content(rc, m.group(1)), out)
        out = _CAPTURE_RE.sub(lambda m: state.get(m.group(1), ""), out)
        out = _VAR_RE.sub(lambda m: state.get(m.group(1), ""), out)
        return out

    @staticmethod
    def _file_content(rc, rel: str) -> str:
        try:
            path = rc.tool_ctx.guard.check_path(rel.strip())
            return path.read_bytes()[:64_000].decode("latin-1")
        except Exception:  # noqa: BLE001 - missing file renders empty
            return ""


def load_declarative_recipes(paths: list[Path]) -> tuple[list[Recipe], list[str]]:
    """Load every JSON recipe pack found under the given dirs."""
    recipes: list[Recipe] = []
    errors: list[str] = []
    for directory in paths:
        directory = Path(directory)
        if not directory.is_dir():
            continue
        for file in sorted(directory.glob("*.json")):
            try:
                spec = json.loads(file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"{file}: {exc}")
                continue
            if not isinstance(spec, dict):
                errors.append(f"{file}: top-level object expected")
                continue
            recipes.append(DeclarativeRecipe(spec, source=file.stem))
    return recipes, errors
