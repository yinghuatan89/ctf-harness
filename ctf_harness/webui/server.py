"""ctfh web - local dashboard backend (standard library only).

Architecture
------------
* ``TaskRegistry`` keeps an in-memory registry of solve tasks.  Each task
  runs the real pipeline in an *isolated subprocess* (``python -m
  ctf_harness solve ...``) so it can be cancelled and cannot crash the UI.
* ``WebUI`` holds the harness components (config / plugins / kb / recipes /
  router) that back the read-only dashboard panels.
* ``WebUIHandler`` serves the static single-page app plus a small JSON API
  (status / solve / tasks / models / recipes / kb / logs).
* Log lines are streamed to the browser via a short-poll ``/api/tasks/<id>``
  endpoint (``?after=N``), which is simpler and more reliable than SSE
  through the stdlib HTTP server.

Security note: the server binds 127.0.0.1 by default and has no
authentication - it is a *local* cockpit. Do not expose it on a public
interface.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import __version__ as HARNESS_VERSION

try:
    from ..config import load_config
    from ..core.challenge import detect_tools
    from ..kb import KnowledgeBase, default_kb_dirs
    from ..llm import Router
    from ..plugins import load_plugins
    from ..solver.recipes import all_recipes
    _HARNESS_IMPORTS = True
except Exception:  # pragma: no cover - partially installed
    _HARNESS_IMPORTS = False

PACKAGE_ROOT = Path(__file__).resolve().parent.parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787

TERMINAL_STATUSES = {"solved", "unsolved", "timeout", "error", "stopped"}


# --------------------------------------------------------------------------- #
# task registry
# --------------------------------------------------------------------------- #
@dataclass
class TaskRecord:
    """A solve task executed in its own subprocess."""

    task_id: str
    name: str
    status: str = "queued"  # queued|running|solved|unsolved|timeout|error|stopped
    flag: str = ""
    via: str = ""
    lane: str = ""
    duration_s: float = 0.0
    exit_code: int | None = None
    error: str = ""
    lines: list[str] = field(default_factory=list)
    session_path: str = ""
    writeup_path: str = ""
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    proc: subprocess.Popen | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_line(self, line: str) -> None:
        with self.lock:
            self.lines.append(line)
            if len(self.lines) > 8000:  # hard cap to protect memory
                self.lines = self.lines[-6000:]

    def snapshot(self, after: int = 0) -> dict:
        with self.lock:
            return {
                "id": self.task_id,
                "name": self.name,
                "status": self.status,
                "flag": self.flag,
                "via": self.via,
                "lane": self.lane,
                "duration_s": self.duration_s,
                "exit_code": self.exit_code,
                "error": self.error[:300],
                "line_count": len(self.lines),
                "lines": self.lines[after:],
                "session_path": self.session_path,
                "writeup_path": self.writeup_path,
                "created_at": self.created_at,
                "finished_at": self.finished_at,
            }


class TaskRegistry:
    def __init__(self, keep: int = 50):
        self._tasks: dict[str, TaskRecord] = {}
        self._keep = keep

    def create(self, name: str) -> TaskRecord:
        task = TaskRecord(task_id=uuid.uuid4().hex[:12], name=name or "challenge")
        self._tasks[task.task_id] = task
        finished = [t for t in self._tasks.values() if t.finished_at is not None]
        if len(self._tasks) > self._keep + 10:
            for t in sorted(finished, key=lambda x: x.finished_at or 0)[
                    : max(0, len(finished) - self._keep)]:
                self._tasks.pop(t.task_id, None)
        return task

    def get(self, task_id: str) -> TaskRecord | None:
        return self._tasks.get(task_id)

    def list(self) -> list[TaskRecord]:
        return sorted(self._tasks.values(), key=lambda t: t.created_at, reverse=True)


# ------------------------------------------------------------------------- #
# UI state + task launcher
# ------------------------------------------------------------------------- #
class WebUI:
    """Holds harness components (read-only panels) + the task registry."""

    def __init__(self, cfg=None):
        self.cfg = cfg if cfg is not None else (load_config() if _HARNESS_IMPORTS else {})
        self.plugins = load_plugins(self.cfg) if _HARNESS_IMPORTS else None
        self.kb = (KnowledgeBase.load(default_kb_dirs()) if _HARNESS_IMPORTS else None)
        self.recipes = all_recipes(self.plugins.recipes) if _HARNESS_IMPORTS else []
        self.router = (Router(self.cfg, extra_provider_types=self.plugins.provider_types)
                       if _HARNESS_IMPORTS else None)
        self.registry = TaskRegistry()

    # ------------------------------------------------------------- read-only
    def status(self) -> dict:
        avail = {}
        if _HARNESS_IMPORTS:
            try:
                avail = detect_tools(refresh=False)
            except Exception:  # pragma: no cover
                avail = {}
        installed = sorted(k for k, ok in avail.items() if ok)
        return {
            "version": HARNESS_VERSION,
            "python": sys.version.split()[0],
            "cwd": str(Path.cwd()),
            "tools": {"installed": installed, "count": len(installed)},
            "recipes": {"total": len(self.recipes)},
            "plugins": {"loaded": (self.plugins.loaded if self.plugins else []),
                        "errors": (self.plugins.errors if self.plugins else [])},
            "kb": (self.kb.stats() if self.kb else None),
            "providers": (self.router.provider_ids() if self.router else []),
        }

    def models(self) -> dict:
        if not self.router:
            return {"providers": [], "roles": {}}
        roles = {}
        for role in ("supervisor", "strategist", "executor", "reflector"):
            try:
                roles[role] = self.router.backend_for(role).describe()
            except Exception as exc:  # noqa: BLE001
                roles[role] = f"({exc})"[:80]
        providers = []
        for pid in self.router.provider_ids():
            try:
                backend = self.router._build(pid)  # noqa: SLF001 - dashboard display
                providers.append({"id": pid, "describe": backend.describe()})
            except Exception as exc:  # noqa: BLE001
                providers.append({"id": pid, "describe": f"error: {exc}"[:80]})
        return {"providers": providers, "roles": roles}

    def ping_models(self) -> list[dict]:
        if not self.router:
            return []
        return self.router.ping_all()

    def recipes_list(self) -> list[dict]:
        out = []
        for r in self.recipes:
            out.append({"id": getattr(r, "id", "?"),
                        "title": getattr(r, "title", ""),
                        "categories": list(getattr(r, "categories", ()) or ()),
                        "description": getattr(r, "description", "")[:200]})
        return out

    def kb_search(self, query: str = "") -> dict:
        if not self.kb:
            return {"stats": None, "hits": []}
        hits = []
        if query:
            text = self.kb.search(query)
            hits = [{"source": chunk.split(") ", 1)[0].strip("("),
                     "text": chunk.split(") ", 1)[1] if ") " in chunk else chunk}
                    for chunk in text.split("\n---\n") if chunk.strip()]
        return {"stats": self.kb.stats(), "hits": hits}

    # --------------------------------------------------------------- solving
    def start_solve(self, payload: dict) -> tuple[TaskRecord | None, str | None]:
        """Launch a solve subprocess; returns (task, error)."""
        challenge = payload.get("challenge") or {}
        path_arg = (challenge.get("path") or "").strip()
        name = (challenge.get("name") or
                (Path(path_arg).name if path_arg else "") or "challenge").strip()
        if not path_arg and not challenge.get("url") and not challenge.get("remote"):
            return None, "provide a challenge path, --url and/or --remote"
        task = self.registry.create(name)

        cmd = [sys.executable, "-m", "ctf_harness", "solve"]
        if path_arg:
            cmd.append(str(path_arg))
        for key, flag in (("url", "--url"), ("remote", "--remote"),
                          ("category", "--category"), ("scorer", "--scorer"),
                          ("flag_format", "--flag-format")):
            value = (challenge.get(key) or "").strip()
            if value:
                cmd += [flag, str(value)]
        mode = (challenge.get("mode") or "").strip()
        if mode:
            cmd += ["--mode", mode]
        budget = (challenge.get("time_budget") or 0)
        try:
            budget = float(budget)
        except (TypeError, ValueError):
            budget = 0.0
        if budget > 0:
            cmd += ["--time-budget", str(budget)]
        if challenge.get("no_llm"):
            cmd.append("--no-llm")
        if challenge.get("no_fast"):
            cmd.append("--no-fast")
        if challenge.get("interactive"):
            cmd.append("--interactive")
        cmd.append("--json")

        run_root = Path.cwd() / "ctfh-web-runs"
        run_root.mkdir(parents=True, exist_ok=True)
        task_run_dir = run_root / task.task_id
        task_run_dir.mkdir(parents=True, exist_ok=True)
        cmd += ["--run-dir", str(task_run_dir)]

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        # Make ``python -m ctf_harness`` resolvable regardless of how the
        # package was installed (source checkout / pip / docker).
        existing_pypath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(PACKAGE_ROOT) + (
            os.pathsep + existing_pypath if existing_pypath else "")
        print(f"[webui] solve cmd: {' '.join(cmd)}", flush=True)
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(Path.cwd()),
                env=env,
            )
        except (OSError, ValueError) as exc:
            task.status = "error"
            task.error = str(exc)[:300]
            task.finished_at = time.time()
            return task, str(exc)[:300]

        task.proc = proc
        task.status = "running"
        task.session_path = str(task_run_dir / ".ctfh" / "session.jsonl")
        task.writeup_path = str(task_run_dir / "writeup.md")
        threading.Thread(target=self._pump, args=(task,), daemon=True,
                         name=f"task-{task.task_id}").start()
        return task, None

    def _pump(self, task: TaskRecord) -> None:
        assert task.proc is not None and task.proc.stdout is not None
        try:
            for raw in task.proc.stdout:
                line = raw.rstrip("\r\n")
                if not line:
                    continue
                task.add_line(line)
                parsed = _parse_json_line(line)
                if parsed:
                    task.flag = parsed.get("flag") or task.flag
                    task.via = parsed.get("via") or task.via
                    task.lane = parsed.get("lane") or task.lane
                    if parsed.get("status"):
                        task.status = parsed["status"]
            task.proc.wait()
            task.exit_code = task.proc.returncode
            if task.status == "running":
                task.status = "solved" if task.flag else "unsolved"
        except Exception as exc:  # noqa: BLE001 - never let pump crash silently
            task.error = f"{type(exc).__name__}: {exc}"[:300]
            task.status = "error"
        finally:
            task.duration_s = round(time.time() - task.created_at, 1)
            task.finished_at = time.time()

    def stop_task(self, task_id: str) -> TaskRecord | None:
        task = self.registry.get(task_id)
        if not task:
            return None
        proc = task.proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            task.status = "stopped"
            task.finished_at = time.time()
        return task


def _parse_json_line(line: str) -> dict:
    """Parse a trailing `ctfh solve --json` result line if present."""
    if not line.startswith("{"):
        return {}
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return {}
    return {"status": data.get("status") or "",
            "flag": data.get("flag") or "",
            "via": data.get("via") or "",
            "lane": data.get("lane") or ""}


# ------------------------------------------------------------------------- #
# HTTP handler
# ------------------------------------------------------------------------- #
class WebUIHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # silence default logging
        pass

    # ------------------------------------------------------------- helpers
    def _send_json(self, obj, code: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        if not path.is_file():
            self._send_json({"error": "not found"}, 404)
            return
        data = path.read_bytes()
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".png": "image/png",
            ".svg": "image/svg+xml",
            ".md": "text/markdown; charset=utf-8",
        }.get(path.suffix.lower(), "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    @property
    def ui(self) -> WebUI:
        return self.server.ui  # type: ignore[attr-defined]

    # ----------------------------------------------------------------- route
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        ui = self.ui

        if path in ("/", "/index.html"):
            self._send_file(STATIC_DIR / "index.html")
            return
        if path.startswith("/static/"):
            rel = path[len("/static/"):].replace("..", "")
            self._send_file(STATIC_DIR / rel)
            return

        if path == "/api/status":
            self._send_json(ui.status())
            return
        if path == "/api/models":
            self._send_json(ui.models())
            return
        if path == "/api/models/ping":
            self._send_json({"rows": ui.ping_models()})
            return
        if path == "/api/recipes":
            self._send_json({"recipes": ui.recipes_list()})
            return
        if path == "/api/kb":
            self._send_json(ui.kb_search((query.get("q") or [""])[0]))
            return
        if path == "/api/tasks":
            rows = [t.snapshot() for t in ui.registry.list()]
            self._send_json({"tasks": rows})
            return
        if path.startswith("/api/tasks/"):
            rest = path[len("/api/tasks/"):]
            parts = rest.split("/", 1)
            task_id = parts[0]
            sub = parts[1] if len(parts) > 1 else ""
            task = ui.registry.get(task_id)
            if not task:
                self._send_json({"error": "task not found"}, 404)
                return
            if sub == "log":
                after = int((query.get("after") or ["0"])[0] or 0)
                self._send_json(task.snapshot(after=after))
                return
            if sub == "writeup" and task.writeup_path:
                wp = Path(task.writeup_path)
                if wp.exists():
                    self._send_file(wp)
                    return
                self._send_json({"error": "writeup missing"}, 404)
                return
            self._send_json(task.snapshot())
            return
        self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        ui = self.ui

        if path == "/api/solve":
            payload = self._read_json()
            task, error = ui.start_solve(payload)
            if error:
                self._send_json({"ok": False, "error": error,
                                 "task": task.snapshot() if task else None}, 400)
                return
            self._send_json({"ok": True, "task": task.snapshot()})
            return

        if path.startswith("/api/tasks/") and path.endswith("/stop"):
            task_id = path[len("/api/tasks/"):-len("/stop")]
            task = ui.stop_task(task_id)
            if not task:
                self._send_json({"error": "task not found"}, 404)
                return
            self._send_json({"ok": True, "task": task.snapshot()})
            return

        self._send_json({"error": "not found"}, 404)


class WebServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, ui: WebUI, host: str, port: int):
        super().__init__((host, port), WebUIHandler)
        self.ui = ui


def create_server(ui: WebUI | None = None, host: str = DEFAULT_HOST,
                  port: int = DEFAULT_PORT) -> WebServer:
    return WebServer(ui or WebUI(), host, port)


def run(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, *,
        open_browser: bool = False) -> int:
    server = create_server(host=host, port=port)
    url = f"http://{host}:{port}/"
    print(f"ctf-harness web UI  ->  {url}")
    print(f"version {HARNESS_VERSION} | press Ctrl+C to stop")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0