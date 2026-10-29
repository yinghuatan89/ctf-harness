"""submit_flag and declare_stuck: loop-control tools."""

from __future__ import annotations

from .base import Tool, ToolContext, ToolError, ToolResult


class SubmitFlagTool(Tool):
    name = "submit_flag"
    description = ("Submit the flag. Triggers verification (scorer endpoint or flag-format "
                   "check); the solve stops immediately when it is accepted.")
    args_help = '{"flag": "flag{...}"}'

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        flag = args.get("flag")
        if not isinstance(flag, str) or not flag.strip():
            raise ToolError("args.flag (string) is required")
        accepted, message = ctx.propose_flag(flag.strip())
        if accepted:
            return ToolResult(True, f"FLAG ACCEPTED: {message}")
        return ToolResult(False, f"FLAG REJECTED: {message}")


class DeclareStuckTool(Tool):
    name = "declare_stuck"
    description = ("Declare that you have no promising ideas left. A stronger reviewer "
                   "model will analyse progress and send a revised strategy.")
    args_help = '{"reason": "leak found but no write primitive"}'

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        reason = args.get("reason") if isinstance(args.get("reason"), str) else ""
        ctx.stuck = True
        return ToolResult(True, "acknowledged - strategy review will trigger.")
