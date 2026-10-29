"""Tool registry + default toolset assembly (plus plugin hook)."""

from __future__ import annotations

from ..safety import GuardError
from .base import Tool, ToolContext, ToolError, ToolResult, bounded_number
from .files import ListFilesTool, ReadFileTool, WriteFileTool
from .http_client import HttpTool
from .notes import ListNotesTool, NoteTool
from .python_exec import RunPythonTool
from .report import ReportTool
from .shell import ShellTool
from .submit import DeclareStuckTool, SubmitFlagTool

__all__ = [
    "Tool", "ToolContext", "ToolError", "ToolResult", "ToolRegistry",
    "build_registry", "bounded_number",
]


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._order: list[str] = []

    def register(self, tool: Tool) -> None:
        if not getattr(tool, "name", "") or tool.name == "?":
            raise ToolError(f"tool {tool!r} has no name")
        if tool.name in self._tools:
            self._order.remove(tool.name)
        self._tools[tool.name] = tool
        self._order.append(tool.name)

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)
        if name in self._order:
            self._order.remove(name)

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    @property
    def names(self) -> list[str]:
        return list(self._order)

    def docs(self) -> str:
        return "\n".join(self._tools[name].docs() for name in self._order)

    def dispatch(self, call: dict, ctx: ToolContext) -> ToolResult:
        name = str(call.get("tool", "")).strip()
        args = call.get("args")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            return ToolResult(False, "ERROR: 'args' must be a JSON object")
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(
                False,
                f"ERROR: unknown tool '{name}'. Available tools: {', '.join(self._order)}")
        try:
            result = tool.run(args, ctx)
            if not isinstance(result, ToolResult):
                result = ToolResult(True, str(result))
        except GuardError as exc:
            result = ToolResult(False, f"BLOCKED (safety): {exc}")
        except ToolError as exc:
            result = ToolResult(False, f"ERROR: {exc}")
        except Exception as exc:  # noqa: BLE001 - observations must never crash the loop
            result = ToolResult(False, f"ERROR: {type(exc).__name__}: {exc}")
        limit = ctx.max_output_chars
        if isinstance(result.output, str) and len(result.output) > limit:
            result.output = (
                result.output[:limit]
                + f"\n...[output truncated, {len(result.output)} chars total]")
            result.truncated = True
        elif not isinstance(result.output, str):
            result.output = str(result.output)
        return result


def build_registry(*, interactive: bool = False, extra_tools: list[Tool] | None = None) -> ToolRegistry:
    registry = ToolRegistry()
    for tool in (
        ShellTool(), RunPythonTool(), ReadFileTool(), WriteFileTool(),
        ListFilesTool(), HttpTool(), NoteTool(), ListNotesTool(),
        SubmitFlagTool(), DeclareStuckTool(), ReportTool(),
    ):
        registry.register(tool)
    if interactive:
        from .ask import AskHumanTool
        registry.register(AskHumanTool())
    for tool in extra_tools or []:
        registry.register(tool)
    return registry
