"""Tool layer: registry, per-challenge execution context, built-in tools.

Every tool gets a ``ToolContext`` holding the workspace, guard, blackboard,
session logger and a ``propose_flag`` callback wired to the race board, so
any lane that finds a flag immediately notifies the whole solve.
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..safety import Guard, GuardError


class ToolError(Exception):
    """Raised by tools for user-facing argument/state errors."""


@dataclass
class ToolResult:
    ok: bool
    output: str
    truncated: bool = False
    meta: dict = field(default_factory=dict)


class Tool:
    name: str = "?"
    description: str = ""
    args_help: str = "{}"

    def run(self, args: dict, ctx: "ToolContext") -> ToolResult:  # noqa: ARG002
        raise NotImplementedError

    def docs(self) -> str:
        arg = self.args_help.replace("\n", " ")
        return f"- {self.name} {arg} : {self.description}"


class ToolContext:
    """Shared per-lane execution context passed to every tool."""

    def __init__(self, *, workspace: Path, guard: Guard, challenge, session,
                 blackboard, propose_flag: Callable[[str], tuple[bool, str]],
                 step_dir: Path, max_output_chars: int = 20000,
                 shell_timeout_s: float = 60.0, python_timeout_s: float = 120.0,
                 lane: str = "main", interactive: bool = False):
        self.workspace = Path(workspace)
        self.guard = guard
        self.challenge = challenge
        self.session = session
        self.blackboard = blackboard
        self.propose_flag = propose_flag
        self.step_dir = Path(step_dir)
        self.max_output_chars = int(max_output_chars)
        self.shell_timeout_s = float(shell_timeout_s)
        self.python_timeout_s = float(python_timeout_s)
        self.lane = lane
        self.interactive = interactive
        self.stuck = False
        self.report: dict | None = None  # set by the report tool (sub-agents)
        self.step_dir.mkdir(parents=True, exist_ok=True)
        self._counter = itertools.count(1)
        self._lock = threading.Lock()

    def next_id(self) -> int:
        with self._lock:
            return next(self._counter)

    def scratch_file(self, suffix: str) -> Path:
        path = self.step_dir / f"run_{self.next_id():03d}{suffix}"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


def bounded_number(value, default: float, low: float, high: float) -> float:
    try:
        number = float(value if value is not None else default)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))
