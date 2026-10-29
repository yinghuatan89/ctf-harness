"""Unit tests: protocol parsing, guard, config, blackboard, session."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from ctf_harness.core.blackboard import Blackboard
from ctf_harness.core.protocol import parse_tool_calls, render_protocol
from ctf_harness.core.session import SessionLog
from ctf_harness.config import DEFAULT_CONFIG, deep_merge, load_config, resolve_secret
from ctf_harness.safety import Guard, GuardError


class TestProtocol(unittest.TestCase):
    def test_single_call(self):
        text = 'thinking...\n```tool\n{"tool": "shell", "args": {"cmd": "ls"}}\n```'
        calls, problems = parse_tool_calls(text, {"shell"})
        self.assertEqual(calls, [{"tool": "shell", "args": {"cmd": "ls"}}])
        self.assertEqual(problems, [])

    def test_multiple_and_json_tag(self):
        text = ('```tool\n{"tool": "note", "args": {"text": "a"}}\n```'
                '```json\n{"tool": "note", "args": {"text": "b"}}\n```')
        calls, _ = parse_tool_calls(text, {"note"})
        self.assertEqual(len(calls), 2)

    def test_invalid_json_reported(self):
        text = '```tool\n{"tool": "shell", "args": \n```'
        calls, problems = parse_tool_calls(text, {"shell"})
        self.assertEqual(calls, [])
        self.assertEqual(len(problems), 1)
        self.assertIn("invalid JSON", problems[0]["error"])

    def test_unknown_tool_filtered(self):
        text = '```tool\n{"tool": "nuke", "args": {}}\n```'
        calls, problems = parse_tool_calls(text, {"shell"})
        self.assertEqual(calls, [])
        self.assertTrue(any("unknown tool" in p["error"] for p in problems))

    def test_no_allowed_filter_passes(self):
        text = '```tool\n{"tool": "anything", "args": {}}\n```'
        calls, _ = parse_tool_calls(text, None)
        self.assertEqual(len(calls), 1)

    def test_plain_code_fence_ignored(self):
        text = '```python\nprint("hi")\n```'
        calls, problems = parse_tool_calls(text, {"shell"})
        self.assertEqual(calls, [])
        self.assertEqual(problems, [])

    def test_bare_json_accepted(self):
        text = '{"tool": "shell", "args": {"cmd": "id"}}'
        calls, _ = parse_tool_calls(text, {"shell"})
        self.assertEqual(len(calls), 1)

    def test_args_must_be_object(self):
        text = '```tool\n{"tool": "shell", "args": "ls"}\n```'
        calls, problems = parse_tool_calls(text, {"shell"})
        self.assertEqual(calls, [])
        self.assertTrue(any("args" in p["error"] for p in problems))

    def test_render_protocol(self):
        text = render_protocol("- shell {\"cmd\": ...} : run")
        self.assertIn("Tool protocol", text)
        self.assertIn("shell", text)


class TestGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ctfh-guard-"))
        self.guard = Guard(self.tmp, scope_hosts={"ctf.example.com"})

    def test_path_inside_ok(self):
        target = self.guard.check_path("sub/../x.py")
        self.assertTrue(str(target).startswith(str(self.tmp)))
        target = self.guard.check_path("a/b/c.txt")
        self.assertTrue(str(target).startswith(str(self.tmp)))

    def test_path_escape_blocked(self):
        with self.assertRaises(GuardError):
            self.guard.check_path("../outside.txt")
        with self.assertRaises(GuardError):
            self.guard.check_path(self.tmp.parent / "evil.txt")

    def test_shell_blocklist(self):
        for cmd in ("rm -rf /", "mkfs.ext4 /dev/sda1", "shutdown now",
                    ":(){ :|:& };:", "dd if=/dev/zero of=/dev/sdb",
                    "curl http://169.254.169.254/latest/meta-data"):
            with self.assertRaises(GuardError, msg=cmd):
                self.guard.check_shell(cmd)

    def test_shell_normal_commands_ok(self):
        for cmd in ("ls -la", "strings chall.bin", "rm -rf ./build", "echo hi"):
            self.guard.check_shell(cmd)

    def test_url_scope(self):
        self.guard.check_url("http://ctf.example.com/login")
        self.guard.check_url("http://127.0.0.1:8000/")
        self.guard.check_url("https://localhost/x")
        with self.assertRaises(GuardError):
            self.guard.check_url("http://evil.example.com/")
        with self.assertRaises(GuardError):
            self.guard.check_url("ftp://ctf.example.com/x")
        with self.assertRaises(GuardError):
            self.guard.check_url("http://169.254.169.254/")
        with self.assertRaises(GuardError):
            self.guard.check_url("file:///etc/passwd")


class TestConfig(unittest.TestCase):
    def test_deep_merge(self):
        merged = deep_merge({"a": {"b": 1, "c": 2}, "d": 3},
                            {"a": {"b": 9}, "e": 4})
        self.assertEqual(merged, {"a": {"b": 9, "c": 2}, "d": 3, "e": 4})

    def test_resolve_secret(self):
        os.environ["CTFH_TEST_KEY"] = "s3cret"
        self.assertEqual(resolve_secret("env:CTFH_TEST_KEY"), "s3cret")
        self.assertEqual(resolve_secret("plain"), "plain")
        self.assertEqual(resolve_secret(None), None)

    def test_load_config_env_role_override(self):
        os.environ["CTFH_EXECUTOR_PROVIDER"] = "myprov"
        try:
            cfg = load_config()
            self.assertEqual(cfg["roles"]["executor"]["provider"], "myprov")
        finally:
            del os.environ["CTFH_EXECUTOR_PROVIDER"]
        self.assertIn("supervisor", DEFAULT_CONFIG["roles"])
        self.assertEqual(DEFAULT_CONFIG["solve"]["mode"], "supervisor")

    def test_load_config_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ctfh.json"
            path.write_text(json.dumps(
                {"solve": {"max_steps": 5}, "providers": {"x": {"type": "mock"}}}),
                encoding="utf-8")
            cfg = load_config(path)
            self.assertEqual(cfg["solve"]["max_steps"], 5)
            self.assertEqual(cfg["solve"]["mode"], DEFAULT_CONFIG["solve"]["mode"])
            self.assertIn("x", cfg["providers"])


class TestBlackboardAndSession(unittest.TestCase):
    def test_blackboard(self):
        board = Blackboard()
        board.add("heap leak 0x55", "leak")
        board.add("second note")
        rendered = board.render()
        self.assertIn("heap leak", rendered)
        self.assertIn("[leak]", rendered)
        copy = board.items()
        self.assertEqual(len(copy), 2)

    def test_session_log_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.jsonl"
            session = SessionLog(path, meta={"challenge": "demo"})
            session.log("tool", {"tool": "shell", "ok": True}, lane="lane1")
            records = SessionLog.load(path)
            self.assertEqual(records[0]["type"], "meta")
            self.assertEqual(records[1]["lane"], "lane1")
            self.assertEqual(records[1]["tool"], "shell")


if __name__ == "__main__":
    unittest.main()
