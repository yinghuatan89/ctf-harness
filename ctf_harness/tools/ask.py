"""ask_human tool (interactive mode only): pull a human into the loop."""

from __future__ import annotations

from .base import Tool, ToolContext, ToolError, ToolResult


class AskHumanTool(Tool):
    name = "ask_human"
    description = ("Ask the human operator for a hint or a decision (only useful when "
                   "the harness runs with --interactive in a terminal).")
    args_help = '{"question": "should I spend more time on heap grooming?"}'

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        question = args.get("question")
        if not isinstance(question, str) or not question.strip():
            raise ToolError("args.question (string) is required")
        if not ctx.interactive:
            return ToolResult(
                False,
                "not in interactive mode - decide autonomously and keep solving, "
                "or declare_stuck if truly blocked.")
        print(f"\n[lane {ctx.lane}] HUMAN INPUT REQUESTED:\n  {question}")
        try:
            answer = input("[you] > ").strip()
        except (EOFError, KeyboardInterrupt):
            return ToolResult(False, "no human input available; continue autonomously.")
        return ToolResult(True, f"HUMAN SAYS: {answer}" if answer else
                          "HUMAN SAYS: (no input; continue autonomously)")
