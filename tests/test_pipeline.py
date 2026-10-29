"""Integration tests: full pipeline (L0/L1/L2 race/L2 supervisor), CTFd
client, report writer, knowledge base, plugin loader. All offline."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ctf_harness.config import DEFAULT_CONFIG, deep_merge
from ctf_harness.core.challenge import Challenge
from ctf_harness.core.orchestrator import Orchestrator, SolveOptions
from ctf_harness.kb import KnowledgeBase
from ctf_harness.llm import Router
from ctf_harness.plugins import PluginRegistry, load_plugins
from ctf_harness.report.writer import write_writeup
from ctf_harness.selftest import FLAGS, _free_port, _start_server
from ctf_harness.tools import build_registry

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
CHALLENGES = EXAMPLES / "challenges"

_STRATEGIST_LINE = ('```json\n{"hypotheses": ['
                    '{"title": "hidden route", "plan": "GET /hidden_flag"},'
                    '{"title": "parameter fuzz", "plan": "fuzz common params"}]}\n```')


def _web_cfg(extra_providers=None, roles=None, solve=None):
    providers = {
        "mock_strat": {"type": "mock", "model": "strat",
                       "lines": [_STRATEGIST_LINE, "fallback advice text"]},
    }
    providers.update(extra_providers or {})
    cfg = deep_merge(DEFAULT_CONFIG, {
        "providers": providers,
        "roles": roles or {"strategist": {"provider": "mock_strat"},
                           "reflector": {"provider": "mock_strat"},
                           "executor": {"provider": "mock_strat"}},
        "solve": solve or {},
    })
    return cfg


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="ctfh-pipe-"))

    def _orchestrator(self, cfg):
        return Orchestrator(cfg, plugins=PluginRegistry(), kb=None,
                            out=lambda *_: None)

    # ------------------------------------------------------------------ L0 e2e
    def test_l0_only_solve(self):
        cfg = deep_merge(DEFAULT_CONFIG, {"solve": {"mode": "single"}})
        challenge = Challenge(name="b64", path=CHALLENGES / "misc_base64",
                               category="misc")
        result = self._orchestrator(cfg).solve(
            challenge, SolveOptions.from_config(cfg, use_llm=False,
                                                time_budget_s=60),
            run_dir=self.work / "b64")
        self.assertTrue(result.solved)
        self.assertEqual(result.flag, FLAGS["base64"])
        self.assertTrue(Path(result.writeup_path).exists())

    # --------------------------------------------------------- L1 web recipe
    def test_web_recipe_solve(self):
        port = _free_port()
        server = _start_server(port)
        try:
            base = f"http://127.0.0.1:{port}"
            cfg = deep_merge(DEFAULT_CONFIG, {"solve": {"mode": "single"}})
            challenge = Challenge(name="web_sqli", category="web", url=f"{base}/",
                                  scorer=f"{base}/check")
            result = self._orchestrator(cfg).solve(
                challenge, SolveOptions.from_config(cfg, use_llm=False,
                                                    time_budget_s=90,
                                                    fast=True, fast_budget_s=5,
                                                    recipe_budget_s=45),
                run_dir=self.work / "web")
            self.assertTrue(result.solved)
            self.assertEqual(result.flag, FLAGS["sqli"])
            self.assertTrue(any("web.sqli_bypass" in r for r in result.recipes_executed))
        finally:
            server.terminate()
            server.wait(timeout=5)

    # ------------------------------------------------------------- L2 race e2e
    def test_race_mode_solve(self):
        port = _free_port()
        server = _start_server(port)
        try:
            base = f"http://127.0.0.1:{port}"
            cfg = _web_cfg(
                extra_providers={
                    "mock_win": {"type": "mock", "model": "win",
                                 "vars": {"PORT": port},
                                 "lines": ['probe now\n```tool\n{"tool": "http", "args": '
                                           '{"method": "GET", "url": '
                                           '"http://127.0.0.1:{PORT}/hidden_flag"}}\n```']},
                    "mock_lose": {"type": "mock", "model": "lose",
                                  "lines": ['```tool\n{"tool": "declare_stuck", "args": '
                                            '{"reason": "no ideas"} }\n```'] * 5},
                },
                roles={"strategist": {"provider": "mock_strat"},
                       "reflector": {"provider": "mock_strat"},
                       "executor": {"provider": "mock_win"}},
                solve={"mode": "race", "lanes": 2,
                       "race_models": [{"provider": "mock_win"},
                                       {"provider": "mock_lose"}],
                       "time_budget_s": 120})
            challenge = Challenge(name="race_demo", category="web",
                                   url=f"{base}/noform", scorer=f"{base}/check")
            result = self._orchestrator(cfg).solve(
                challenge, SolveOptions.from_config(cfg, fast=False),
                run_dir=self.work / "race")
            self.assertTrue(result.solved)
            self.assertEqual(result.flag, FLAGS["supervisor"])
            self.assertEqual(result.lane, "lane1")
        finally:
            server.terminate()
            server.wait(timeout=5)

    # ------------------------------------------------------- L2 supervisor e2e
    def test_supervisor_mode_solve(self):
        port = _free_port()
        server = _start_server(port)
        try:
            base = f"http://127.0.0.1:{port}"
            cfg = _web_cfg(
                extra_providers={
                    "mock_sup": {"type": "mock", "model": "sup",
                                 "script": str(EXAMPLES / "mock" / "supervisor_script.jsonl")},
                    "mock_exec": {"type": "mock", "model": "exec",
                                  "script": str(EXAMPLES / "mock" / "web_executor_script.jsonl"),
                                  "vars": {"PORT": port}},
                },
                roles={"supervisor": {"provider": "mock_sup"},
                       "strategist": {"provider": "mock_sup"},
                       "reflector": {"provider": "mock_sup"},
                       "executor": {"provider": "mock_exec"}},
                solve={"mode": "supervisor", "supervisor_rounds": 2,
                       "subagent_steps": 4, "subagents_parallel": 2,
                       "time_budget_s": 120})
            challenge = Challenge(name="supervisor_demo", category="web",
                                   url=f"{base}/noform", scorer=f"{base}/check")
            result = self._orchestrator(cfg).solve(
                challenge, SolveOptions.from_config(cfg, fast=False),
                run_dir=self.work / "supervisor")
            self.assertTrue(result.solved)
            self.assertEqual(result.flag, FLAGS["supervisor"])
            self.assertTrue(any(getattr(lane, "task_id", "") == "t1"
                                for lane in result.lanes))
        finally:
            server.terminate()
            server.wait(timeout=5)

    # ------------------------------------------------------------------ report
    def test_report_writer(self):
        from ctf_harness.core.session import SessionLog
        session = SessionLog(self.work / "s" / "session.jsonl",
                              meta={"challenge": "demo"})
        session.log("l0_scan", {"findings": ["flag{demo} via base64"]})
        session.log("tool", {"tool": "shell", "args": {"cmd": "ls"},
                             "ok": True, "output": "file1"})
        session.log("flag_found", {"flag": "flag{demo}"}, lane="lane1")
        out = write_writeup(session.path, self.work / "writeup.md",
                            {"challenge": "demo", "status": "solved",
                             "flag": "flag{demo}", "via": "L0/base64"})
        text = Path(out).read_text(encoding="utf-8")
        self.assertIn("# Writeup: demo", text)
        self.assertIn("FLAG FOUND", text)
        self.assertIn("flag{demo}", text)
        self.assertIn("shell", text)


class TestKnowledgeBase(unittest.TestCase):
    def test_load_and_search(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "notes.md").write_text(
                "# topic\n\nThe padding oracle attack targets CBC mode with "
                "distinguishable error responses per decrypted byte.\n\n"
                "Unrelated paragraph about cooking recipes for dinner.",
                encoding="utf-8")
            kb = KnowledgeBase.load([root])
            self.assertGreaterEqual(kb.stats()["paragraphs"], 1)
            hit = kb.search("cbc padding oracle error responses byte")
            self.assertIn("padding oracle", hit.lower())
            miss = kb.search("zzzz qqqq unrelated gibberish")
            self.assertEqual(miss, "")


class TestPluginLoader(unittest.TestCase):
    PLUGIN_SRC = '''
from ctf_harness.tools.base import Tool, ToolResult

class EchoTool(Tool):
    name = "echo_tool"
    description = "echoes text (test plugin)"
    args_help = '{"text": "..."}'

    def run(self, args, ctx):
        return ToolResult(True, "echo:" + str(args.get("text", "")))

def register(reg):
    reg.register_tool(EchoTool())
    reg.on("flag_found", lambda payload: None)
'''

    def test_load_python_plugin_and_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "my_plugin.py").write_text(self.PLUGIN_SRC, encoding="utf-8")
            (root / "recipes.d").mkdir()
            (root / "recipes.d" / "pack.json").write_text(
                json.dumps({"id": "user.pack", "title": "pack",
                            "steps": [{"tool": "shell",
                                       "args": {"cmd": "echo {{name}}"}}]}),
                encoding="utf-8")
            cfg = deep_merge(DEFAULT_CONFIG, {
                "plugins": {"paths": [str(root)]},
                "recipes": {"paths": [str(root / "recipes.d")]},
            })
            registry = load_plugins(cfg)
            self.assertIn("my_plugin.py", registry.loaded)
            self.assertIn("echo_tool", [getattr(t, "name", "") for t in registry.tools])
            self.assertIn("flag_found", registry.hooks)
            self.assertIn("user.pack", [r.id for r in registry.recipes])

            tools = build_registry(interactive=False, extra_tools=registry.tools)
            from ctf_harness.core.blackboard import Blackboard
            from ctf_harness.core.session import SessionLog
            from ctf_harness.safety import Guard
            from ctf_harness.tools import ToolContext
            ctx = ToolContext(
                workspace=root, guard=Guard(root), challenge=Challenge(name="x"),
                session=SessionLog(root / "session.jsonl"),
                blackboard=Blackboard(), propose_flag=lambda f: (True, "ok"),
                step_dir=root / "steps")
            result = tools.dispatch({"tool": "echo_tool", "args": {"text": "hi"}},
                                     ctx)
            self.assertEqual(result.output, "echo:hi")

    def test_broken_plugin_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "broken.py").write_text("raise RuntimeError('boom')",
                                            encoding="utf-8")
            cfg = deep_merge(DEFAULT_CONFIG, {"plugins": {"paths": [str(root)]}})
            registry = load_plugins(cfg)
            self.assertTrue(registry.errors)
            self.assertEqual(registry.loaded, [])


class _FakeCTFdHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/api/v1/challenges":
            self._json(200, {"data": [{"id": 1, "name": "Web 1", "category": "Web",
                                       "value": 100, "state": "visible"}]})
        elif self.path == "/api/v1/challenges/1":
            self._json(200, {"data": {
                "id": 1, "name": "Web 1", "category": "Web",
                "description": "attack http://127.0.0.1:1/",
                "files": [f"http://127.0.0.1:{self.server.server_address[1]}/files/a.txt"]}})
        elif self.path == "/files/a.txt":
            body = b"challenge file contents"
            self.send_response(200)
            self.send_header("Content-Disposition",
                             'attachment; filename="a.txt"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json(404, {})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/api/v1/submissions":
            correct = payload.get("submission") == "flag{right}"
            self._json(200, {"data": {"status": "correct" if correct else "incorrect",
                                      "message": "ok"}})
        else:
            self._json(404, {})


class TestCTFdClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeCTFdHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_full_client_flow(self):
        from ctf_harness.ctfd.client import CTFdClient, CTFdError
        client = CTFdClient(self.base, token="tok")
        items = client.list_challenges()
        self.assertEqual(items[0]["name"], "Web 1")
        details = client.get_challenge(1)
        self.assertIn("files", details)
        with tempfile.TemporaryDirectory() as tmp:
            downloaded = client.download_file(details["files"][0], Path(tmp) / "dl")
            self.assertEqual(downloaded.name, "a.txt")
            self.assertEqual(downloaded.read_bytes(), b"challenge file contents")
        self.assertTrue(client.submit_flag(1, "flag{right}")["correct"])
        self.assertFalse(client.submit_flag(1, "flag{wrong}")["correct"])

    def test_bad_url_rejected(self):
        from ctf_harness.ctfd.client import CTFdClient, CTFdError
        with self.assertRaises(CTFdError):
            CTFdClient("not-a-url")


if __name__ == "__main__":
    unittest.main()
