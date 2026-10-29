"""Shell tool: run CLI commands inside the challenge workspace."""

from __future__ import annotations

import subprocess

from .base import Tool, ToolContext, ToolError, ToolResult, bounded_number


class ShellTool(Tool):
    name = "shell"
    description = ("Run a shell command (non-interactive, cwd = challenge workspace). "
                   "Use for CLI tools like strings/objdump/binwalk; prefer run_python for scripting.")
    args_help = '{"cmd": "ls -la", "timeout": 60}'

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        cmd = args.get("cmd")
        if not isinstance(cmd, str) or not cmd.strip():
            raise ToolError("args.cmd (string) is required")
        timeout = bounded_number(args.get("timeout"), ctx.shell_timeout_s, 1, 600)
        ctx.guard.check_shell(cmd)
        try:
            proc = subprocess.run(
                cmd, shell=True, cwd=str(ctx.workspace),
                capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return ToolResult(False, f"TIMEOUT: command exceeded {timeout:.0f}s")
        except OSError as exc:
            return ToolResult(False, f"ERROR: cannot spawn shell: {exc}")
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
        parts = [f"exit={proc.returncode}"]
        if stdout.strip():
            parts.append("--- stdout ---\n" + stdout.rstrip())
        if stderr.strip():
            parts.append("--- stderr ---\n" + stderr.rstrip())
        if not stdout.strip() and not stderr.strip():
            parts.append("(no output)")
        return ToolResult(proc.returncode == 0, "\n".join(parts))
