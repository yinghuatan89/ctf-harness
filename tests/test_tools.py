"""Unit tests: the tool layer (shell, python, files, http, submit/report/notes)."""

from __future__ import annotations

import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ctf_harness.core.blackboard import Blackboard
from ctf_harness.core.challenge import Challenge
from ctf_harness.core.session import SessionLog
from ctf_harness.safety import Guard
from ctf_harness.tools import ToolContext, build_registry
from ctf_harness.tools.base import ToolResult


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _send(self, status, body):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        if self.path == "/ok":
            self._send(200, "hello from server")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
        else:
            self._send(404, "nope")


class TestTools(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="ctfh-tools-"))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.registry = build_registry()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _ctx(self, **overrides):
        defaults = dict(
            workspace=self.tmp, guard=Guard(self.tmp, scope_hosts=set()),
            challenge=Challenge(name="t", path=self.tmp),
            session=SessionLog(self.tmp / ".ctfh" / "session.jsonl"),
            blackboard=Blackboard(),
            propose_flag=lambda flag: (True, "accepted"),
            step_dir=self.tmp / ".ctfh" / "main",
            lane="main")
        defaults.update(overrides)
        return ToolContext(**defaults)

    def _dispatch(self, tool, **args):
        return self.registry.dispatch({"tool": tool, "args": args}, self._ctx())

    # ------------------------------------------------------------------ shell
    def test_shell_echo(self):
        result = self._dispatch("shell", cmd="echo harness-test-ok")
        self.assertTrue(result.ok)
        self.assertIn("harness-test-ok", result.output)

    def test_shell_guard_blocks(self):
        result = self._dispatch("shell", cmd="rm -rf /")
        self.assertFalse(result.ok)
        self.assertIn("BLOCKED", result.output)

    def test_shell_timeout(self):
        import sys
        result = self._dispatch("shell",
                                cmd=f"{sys.executable} -c \"import time; time.sleep(5)\"",
                                timeout=1)
        self.assertFalse(result.ok)
        self.assertIn("TIMEOUT", result.output)

    # ----------------------------------------------------------------- python
    def test_run_python(self):
        result = self._dispatch("run_python", code="print(6 * 7)")
        self.assertTrue(result.ok)
        self.assertIn("42", result.output)

    def test_run_python_error(self):
        result = self._dispatch("run_python", code="raise ValueError('boom')")
        self.assertFalse(result.ok)
        self.assertIn("ValueError", result.output)

    # ------------------------------------------------------------------ files
    def test_file_roundtrip_and_listing(self):
        write = self._dispatch("write_file", path="sub/note.txt", content="hello file")
        self.assertTrue(write.ok)
        read = self._dispatch("read_file", path="sub/note.txt")
        self.assertIn("hello file", read.output)
        listing = self._dispatch("list_files", path=".")
        self.assertIn("sub/note.txt", listing.output)

    def test_read_binary_gives_hexdump(self):
        (self.tmp / "blob.bin").write_bytes(bytes(range(256)))
        result = self._dispatch("read_file", path="blob.bin")
        self.assertIn("0000", result.output)
        self.assertIn("printable strings", result.output)

    def test_read_escape_blocked(self):
        result = self._dispatch("read_file", path="../outside.txt")
        self.assertFalse(result.ok)
        self.assertIn("BLOCKED", result.output)

    # ------------------------------------------------------------------- http
    def test_http_get_and_redirect(self):
        result = self._dispatch("http", method="GET",
                                url=f"http://127.0.0.1:{self.port}/ok")
        self.assertTrue(result.ok)
        self.assertIn("hello from server", result.output)

        redirected = self._dispatch("http", method="GET",
                                    url=f"http://127.0.0.1:{self.port}/redirect")
        self.assertTrue(redirected.ok)
        self.assertIn("hello from server", redirected.output)

    def test_http_error_is_observation(self):
        result = self._dispatch("http", method="GET",
                                url=f"http://127.0.0.1:{self.port}/missing")
        self.assertFalse(result.ok)
        self.assertIn("HTTP 404", result.output)

    def test_http_scope_enforced(self):
        result = self._dispatch("http", method="GET", url="http://example.com/")
        self.assertFalse(result.ok)
        self.assertIn("BLOCKED", result.output)

    # -------------------------------------------------------- notes / control
    def test_notes(self):
        ctx = self._ctx()
        self.registry.dispatch(
            {"tool": "note", "args": {"text": "canditate offset 42", "tag": "finding"}},
            ctx)
        listing = self.registry.dispatch({"tool": "list_notes", "args": {}}, ctx)
        self.assertIn("canditate offset 42", listing.output)

    def test_submit_flag_accept(self):
        result = self._dispatch("submit_flag", flag="flag{test_win}")
        self.assertTrue(result.ok)
        self.assertIn("FLAG ACCEPTED", result.output)

    def test_submit_flag_reject_duplicate(self):
        attempts = []

        def propose(flag):
            attempts.append(flag)
            if len(attempts) > 1:
                return False, "duplicate"
            return True, "first"

        self.registry.dispatch(
            {"tool": "submit_flag", "args": {"flag": "flag{x}"}},
            self._ctx(propose_flag=propose))
        self.assertEqual(len(attempts), 1)

    def test_report_tool_sets_context(self):
        ctx = self._ctx()
        self.assertIsNone(ctx.report)
        result = self.registry.dispatch(
            {"tool": "report", "args": {"status": "done",
                                        "conclusion": "task complete"}},
            ctx)
        self.assertTrue(result.ok)
        self.assertEqual(ctx.report["status"], "done")
        self.assertEqual(ctx.report["conclusion"], "task complete")

    def test_declare_stuck(self):
        ctx = self._ctx()
        result = self.registry.dispatch(
            {"tool": "declare_stuck", "args": {"reason": "no ideas"}}, ctx)
        self.assertTrue(result.ok)
        self.assertTrue(ctx.stuck)

    def test_output_truncation(self):
        ctx = self._ctx()
        limit = ctx.max_output_chars

        class _Boom:
            name = "boom"
            args_help = "{}"
            description = "boom"

            def run(self, args, ctx):
                return ToolResult(True, "y" * 60_000)

        registry = build_registry()
        registry.register(_Boom())
        out = registry.dispatch({"tool": "boom", "args": {}}, ctx)
        self.assertTrue(out.truncated)
        self.assertLessEqual(len(out.output), limit + 100)
        self.assertIn("truncated", out.output)


if __name__ == "__main__":
    unittest.main()
