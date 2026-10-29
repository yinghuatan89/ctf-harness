"""File tools: read (text/binary with hexdump+strings), write, list."""

from __future__ import annotations

import re

from .base import Tool, ToolContext, ToolError, ToolResult, bounded_number

_STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:512]
    bad = sum(1 for b in sample if b < 9 or (13 < b < 32) or b > 126)
    return bad / max(1, len(sample)) > 0.10 or b"\x00" in sample[:64]


def _hexdump(data: bytes, limit: int = 1024) -> str:
    lines = []
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset:offset + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hexpart:<47}  {asciipart}")
    if len(data) > limit:
        lines.append(f"... ({len(data)} bytes total)")
    return "\n".join(lines)


def _extract_strings(data: bytes, cap: int = 4000) -> str:
    out = [m.group(0).decode("ascii", "replace") for m in _STRING_RE.finditer(data)]
    joined = "\n".join(out)
    if len(joined) > cap:
        return joined[:cap] + f"\n...[{len(joined) - cap} chars truncated]"
    return joined


class ReadFileTool(Tool):
    name = "read_file"
    description = ("Read a file from the challenge workspace. Text files return raw text; "
                   "binary files return a hexdump plus extracted printable strings.")
    args_help = '{"path": "chall.bin", "max_bytes": 65536}'

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        path_arg = args.get("path")
        if not isinstance(path_arg, str) or not path_arg.strip():
            raise ToolError("args.path (string) is required")
        path = ctx.guard.check_path(path_arg)
        if not path.exists():
            raise ToolError(f"file not found: {path_arg}")
        if path.is_dir():
            raise ToolError(f"{path_arg} is a directory; use list_files")
        max_bytes = int(bounded_number(args.get("max_bytes"), 65536, 64, 262144))
        total = path.stat().st_size
        data = path.read_bytes()[:max_bytes]
        if _looks_binary(data):
            parts = [
                f"binary file, {total} bytes (showing first {len(data)})",
                _hexdump(data),
            ]
            strings = _extract_strings(data)
            if strings:
                parts.append("--- printable strings ---\n" + strings)
            return ToolResult(True, "\n".join(parts))
        text = data.decode("utf-8", "replace")
        if total > max_bytes:
            text += f"\n...[truncated, {total} bytes total]"
        return ToolResult(True, text)


class WriteFileTool(Tool):
    name = "write_file"
    description = "Write a text file into the challenge workspace (creates parent dirs)."
    args_help = '{"path": "solver.py", "content": "..."}'

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        path_arg = args.get("path")
        content = args.get("content")
        if not isinstance(path_arg, str) or not path_arg.strip():
            raise ToolError("args.path (string) is required")
        if not isinstance(content, str):
            raise ToolError("args.content (string) is required")
        path = ctx.guard.check_path(path_arg, write=True)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return ToolResult(True, f"wrote {len(content)} bytes to {path_arg}")


class ListFilesTool(Tool):
    name = "list_files"
    description = "List files in the challenge workspace (recursive, with sizes)."
    args_help = '{"path": ".", "max_entries": 300}'

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = ctx.guard.check_path(args.get("path") or ".")
        if not base.exists():
            raise ToolError(f"path not found: {args.get('path')}")
        max_entries = int(bounded_number(args.get("max_entries"), 300, 10, 2000))
        if base.is_file():
            return ToolResult(True, f"{base.name}  [{base.stat().st_size} bytes]")
        lines: list[str] = []
        for entry in sorted(base.rglob("*")):
            if len(lines) >= max_entries:
                lines.append(f"... (more than {max_entries} entries)")
                break
            rel = entry.relative_to(base)
            if any(part in {".ctfh", "__pycache__", ".git"} for part in rel.parts):
                continue
            if entry.is_dir():
                lines.append(f"  {rel.as_posix()}/")
            else:
                try:
                    lines.append(f"{entry.stat().st_size:>10}  {rel.as_posix()}")
                except OSError:
                    lines.append(f"{'?':>10}  {rel.as_posix()}")
        return ToolResult(True, "\n".join(lines) or "(empty directory)")
