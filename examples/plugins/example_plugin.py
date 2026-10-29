"""Example ctf-harness plugin: a custom tool + a flag-found hook.

Copy this file into ./plugins/ (or ~/.ctfh/plugins/) to activate it.
Plugins are arbitrary code - only install plugins you trust.
"""

from __future__ import annotations


def register(reg):
    from ctf_harness.solver.heuristics import Finding
    from ctf_harness.tools.base import Tool, ToolResult

    class RotNTool(Tool):
        name = "rotn"
        description = ("ROT-N decode: tries every shift and returns the first "
                       "one containing a flag-like token (otherwise shift 13).")
        args_help = '{"text": "..."}'

        def run(self, args, ctx):
            text = args.get("text")
            if not isinstance(text, str):
                text = str(text or "")
            import re
            for shift in range(26):
                shifted = "".join(
                    chr((ord(c) - 65 + shift) % 26 + 65) if "A" <= c <= "Z" else
                    chr((ord(c) - 97 + shift) % 26 + 97) if "a" <= c <= "z" else c
                    for c in text)
                if re.search(r"(?i)flag\{", shifted):
                    return ToolResult(True, f"shift={shift}\n{shifted}")
            return ToolResult(True, "no flag-like rotation found (tried 26)")

    reg.register_tool(RotNTool())

    class CustomNoteRecipe:
        pass  # recipes use the Recipe dataclass; see docs/RECIPES.md

    def on_flag(payload):
        print(f"[example-plugin] flag found on '{payload.get('name')}': "
              f"{payload.get('flag')} via {payload.get('via')}")

    reg.on("flag_found", on_flag)
