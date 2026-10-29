"""Blackboard notes tools: persistent facts carried across every step."""

from __future__ import annotations

from .base import Tool, ToolContext, ToolError, ToolResult


class NoteTool(Tool):
    name = "note"
    description = ("Persist an important fact (leaks, addresses, vuln class, creds, "
                   "partial progress). Notes are shown to you on every later step.")
    args_help = '{"text": "heap leak = 0x55..aa", "tag": "leak"}'

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        text = args.get("text")
        if not isinstance(text, str) or not text.strip():
            raise ToolError("args.text (string) is required")
        tag = args.get("tag")
        if not isinstance(tag, str) or not tag.strip():
            tag = "note"
        ctx.blackboard.add(text.strip(), tag.strip()[:24])
        return ToolResult(True, "noted.")


class ListNotesTool(Tool):
    name = "list_notes"
    description = "Show all facts on the blackboard."
    args_help = "{}"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:  # noqa: ARG002
        rendered = ctx.blackboard.render()
        return ToolResult(True, rendered if rendered else "(no notes yet)")
