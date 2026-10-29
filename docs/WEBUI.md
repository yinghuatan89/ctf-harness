# Web Dashboard (GUI)

`ctfh web` starts a local, zero-dependency web cockpit for the harness.
It is a single-page app (no build step, no CDN, no framework) served by the
Python standard library HTTP server, so it runs on Windows / Linux / macOS
and inside Docker alike.

## Quick start

```bash
# from the project root (or any directory, as long as ctf-harness is importable)
ctfh web --host 127.0.0.1 --port 8787 --open
```

Then open <http://127.0.0.1:8787/>.

The solve tasks are executed in isolated subprocesses
(`python -m ctf_harness solve ...`), so:

* the UI thread never blocks on tool calls or LLM latency;
* a running task can be cancelled with the *Stop* button;
* a crashed solver cannot take the dashboard down.

## Panels

| Panel      | Purpose                                                            |
|------------|--------------------------------------------------------------------|
| 工作台     | create a challenge (path / URL / remote / category / flag format), start the L0→L1→L2→L3 pipeline, watch live logs, get the flag banner and writeup link |
| 任务历史   | all tasks started from the dashboard with status / flag / runtime   |
| 模型配置   | configured providers and role→backend mapping, one-click latency ping |
| 预案库     | built-in + user recipe packs (L1 stage)                             |
| 知识库     | KB stats and keyword search                                         |
| 系统状态   | version, python, detected tools, plugins, KB and providers          |

## API

Read-only panels and the solve flow are plain JSON endpoints:

| Method | Path                          | Description                          |
|--------|-------------------------------|--------------------------------------|
| GET    | `/api/status`                 | version / tools / plugins / kb / providers |
| GET    | `/api/models`                 | providers + role mapping              |
| GET    | `/api/models/ping`           | provider latency table                |
| GET    | `/api/recipes`               | recipe list                           |
| GET    | `/api/kb?q=...`              | knowledge base search                 |
| GET    | `/api/tasks`                 | task history                          |
| GET    | `/api/tasks/<id>`            | task snapshot                         |
| GET    | `/api/tasks/<id>/log?after=N`| incremental log lines                |
| GET    | `/api/tasks/<id>/writeup`    | generated writeup (Markdown)         |
| POST   | `/api/solve`                 | start a solve task (JSON body)       |
| POST   | `/api/tasks/<id>/stop`       | cancel a running task                |

Example solve payload:

```json
{
  "challenge": {
    "name": "web_calc",
    "category": "web",
    "path": "/abs/path/to/challenge",
    "url": "http://target:8080/",
    "flag_format": "(?i)flag\\{[^}\\s]{1,128}\\}",
    "mode": "supervisor",
    "time_budget": 600,
    "no_llm": false
  }
}
```

Tasks write their workspace under `./ctfh-web-runs/<task_id>/`
(session.jsonl + writeup.md), which is gitignored.

## Security

The server binds `127.0.0.1` by default and has **no authentication** - it
is a local cockpit. Do not expose it on a public interface. If you do want
remote access (e.g. over a VPN), run with `--host 0.0.0.0` and put a
reverse proxy / SSO in front of it.

## Docker

```bash
docker build -t ctf-harness .
docker run -p 8787:8787 \
  -v "$(pwd)/kb:/app/kb" \
  -v "$(pwd)/ctfh.json:/app/ctfh.json" \
  ctf-harness
```

or with compose (mounts kb / config / plugins / recipes / runs - see
`docker-compose.yml`):

```bash
docker compose up -d
# open http://localhost:8787
```

The image runs `ctfh web --host 0.0.0.0 --port 8787` by default.

> AI生成
