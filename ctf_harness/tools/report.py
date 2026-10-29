"""report tool: how a specialist sub-agent ends its run with a distilled result."""

from __future__ import annotations

from .base import Tool, ToolContext, ToolError, ToolResult

_VALID_STATUS = ("done", "blocked", "failed")


class ReportTool(Tool):
    name = "report"
    description = ("SUB-AGENT ONLY: submit your final task report and end this run. "
                    "Use when the assigned brief is fulfilled (or provably impossible). "
                    "Keep the conclusion dense: facts, offsets, payloads - no fluff.")
    args_help = ('{"status": "done|blocked|failed", "conclusion": "what you '
                 'established (concrete, <=150 words)", "findings": ["..."], '
                 '"next": "single most valuable next action for the supervisor"}')

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        if not isinstance(args.get("conclusion"), str) or not args["conclusion"].strip():
            raise ToolError("args.conclusion (string) is required")
        status = str(args.get("status") or "done").lower()
        if status not in _VALID_STATUS:
            status = "done"
        findings = args.get("findings") or []
        if not isinstance(findings, list):
            findings = [str(findings)]
        ctx.report = {
            "status": status,
            "conclusion": args["conclusion"].strip()[:1500],
            "findings": [str(f)[:200] for f in findings[:8]],
            "next": str(args.get("next") or "").strip()[:500],
        }
        return ToolResult(True, "report recorded - this task run ends now.")
