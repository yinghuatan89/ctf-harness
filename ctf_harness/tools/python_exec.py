"""run_python tool: write + execute Python scripts in an isolated process."""

from __future__ import annotations

import subprocess
import sys

from .base import Tool, ToolContext, ToolError, ToolResult, bounded_number


class RunPythonTool(Tool):
    name = "run_python"
    description = ("Write and run a Python 3 script (stdlib only guaranteed; cwd = workspace). "
                   "Best for solvers, decoders, socket/pwntools-style exploits and anything scripted. "
                   "The script file is kept in the lane dir for the writeup.")
    args_help = '{"code": "print(2+2)", "timeout": 120}'

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        code = args.get("code")
        if not isinstance(code, str) or not code.strip():
            raise ToolError("args.code (string python source) is required")
        timeout = bounded_number(args.get("timeout"), ctx.python_timeout_s, 1, 600)
        path = ctx.scratch_file(".py")
        try:
            path.write_text(code, encoding="utf-8")
        except OSError as exc:
            return ToolResult(False, f"ERROR: cannot write script: {exc}")
        try:
            proc = subprocess.run(
                [sys.executable, "-X", "utf8", "-B", str(path)],
                cwd=str(ctx.workspace), capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return ToolResult(False, f"TIMEOUT: script exceeded {timeout:.0f}s", meta={"script": path.name})
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
        parts = [f"exit={proc.returncode}"]
        if stdout.strip():
            parts.append("--- stdout ---\n" + stdout.rstrip())
        if stderr.strip():
            parts.append("--- stderr ---\n" + stderr.rstrip())
        if not stdout.strip() and not stderr.strip():
            parts.append("(no output)")
        parts.append(f"(script saved as .ctfh/{ctx.lane}/{path.name})")
        return ToolResult(
            proc.returncode == 0, "\n".join(parts), meta={"script": path.name})
