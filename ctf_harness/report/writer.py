"""Turn a session.jsonl replay into a human-readable writeup."""

from __future__ import annotations

from pathlib import Path

from ..core.session import SessionLog


def write_writeup(session_path, out_path, meta: dict) -> Path:
    records = SessionLog.load(Path(session_path))
    lines: list[str] = [f"# Writeup: {meta.get('challenge', 'challenge')}", ""]

    lines.append("| field | value |")
    lines.append("|---|---|")
    for key in ("category", "url", "remote", "status", "flag", "via", "duration_s"):
        value = meta.get(key)
        if value not in (None, ""):
            lines.append(f"| {key} | {value} |")
    lines.append("")
    lines.append("## Timeline")
    lines.append("")

    for record in records:
        kind = record.get("type")
        lane = record.get("lane", "main")
        if kind == "meta":
            continue
        if kind == "l0_scan":
            lines.append(f"- **L0** heuristic findings: {record.get('findings')}")
        elif kind == "l1_recipes":
            lines.append(f"- **L1** recipes executed: {record.get('executed')}")
        elif kind == "playbook":
            lines.append(f"- **L2** playbook `{record.get('id')}` ({record.get('title')})")
        elif kind == "supervisor_dispatch":
            lines.append(f"- **L2** supervisor dispatch {record.get('tasks')} "
                         f"(roles: {record.get('roles')}, budget {record.get('budget_s')}s)")
        elif kind == "supervisor_done":
            for line in record.get("reports") or []:
                lines.append(f"- **L2** report: {line}")
        elif kind == "assistant":
            text = (record.get("text") or "").replace("\n", " ")[:220]
            lines.append(f"- `{lane}` reasoning: {text}")
        elif kind == "tool":
            output = (record.get("output") or "").replace("\n", " ")[:200]
            lines.append(f"- `{lane}` tool **{record.get('tool')}** "
                         f"({record.get('args')}) -> "
                         f"{'ok' if record.get('ok') else 'error'}: {output}")
        elif kind == "flag_attempt":
            lines.append(f"- `{lane}` flag attempt `{record.get('flag')}` "
                         f"accepted={record.get('accepted')}")
        elif kind == "flag_found":
            lines.append(f"- **FLAG FOUND** `{record.get('flag')}` on lane `{lane}`")
        elif kind == "reflect":
            advice = (record.get("advice") or "").replace("\n", " ")[:200]
            lines.append(f"- `{lane}` reflector advice: {advice}")
        elif kind == "result":
            lines.append(f"- **RESULT** {record.get('status')} "
                         f"flag=`{record.get('flag')}` in {record.get('duration_s')}s")
        elif kind == "scorer":
            lines.append(f"- `{lane}` scorer response: {record.get('response')}")

    out_path = Path(out_path)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path
