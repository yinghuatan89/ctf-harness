"""Unit tests: LLM backends (mock + openai_compatible against a fake server)
and the router (role resolution, fallback chains, circuit breaker)."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ctf_harness.config import DEFAULT_CONFIG, deep_merge
from ctf_harness.llm import LLMError, Message, Router
from ctf_harness.llm.providers import MockBackend, OpenAICompatibleBackend


class _FakeOpenAIHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        if "/fail" in self.path:
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        content = f"echo:{body['messages'][-1]['content']}"
        payload = json.dumps({"choices": [{"message": {"content": content}}]})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload.encode())


class TestMockBackend(unittest.TestCase):
    def test_scripted_lines_and_vars(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "script.jsonl"
            script.write_text(
                '{"content": "hello {NAME}"}\n'
                '{"content": "```tool\\n{\\"tool\\": \\"shell\\", \\"args\\": {\\"cmd\\": \\"{PORT}\\"}}\\n```"}\n',
                encoding="utf-8")
            backend = MockBackend(model="m", script=str(script),
                                  vars={"NAME": "world", "PORT": 8080})
            first = backend.chat([Message("user", "hi")])
            self.assertEqual(first, "hello world")
            second = backend.chat([Message("user", "go")])
            self.assertIn('"cmd": "8080"', second)
            third = backend.chat([Message("user", "go")])
            self.assertIn("declare_stuck", third)
            self.assertEqual(backend.consumed, 2)  # exhaustion return is not a script line


class TestOpenAICompatible(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOpenAIHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_chat_roundtrip(self):
        backend = OpenAICompatibleBackend(
            model="test-model",
            base_url=f"http://127.0.0.1:{self.port}/v1",
            api_key="k", max_retries=0)
        reply = backend.chat([Message("system", "s"), Message("user", "ping")])
        self.assertEqual(reply, "echo:ping")
        ok, ms, err = backend.ping()
        self.assertTrue(ok)
        self.assertGreaterEqual(ms, 0)
        self.assertEqual(err, "")

    def test_http_error_raises(self):
        backend = OpenAICompatibleBackend(
            model="x", base_url=f"http://127.0.0.1:{self.port}/fail",
            api_key="k", max_retries=0)
        with self.assertRaises(LLMError):
            backend.chat([Message("user", "x")], max_tokens=8)


class TestRouter(unittest.TestCase):
    def _cfg(self, providers, roles=None):
        return deep_merge(DEFAULT_CONFIG, {
            "providers": providers,
            "roles": roles or {},
        })

    def test_role_resolution_and_inheritance(self):
        cfg = self._cfg({
            "strong": {"type": "mock", "model": "big", "lines": ["from-big"] * 5},
            "fast": {"type": "mock", "model": "small", "lines": ["from-small"] * 5},
        }, roles={"executor": {"provider": "fast"},
                  "reflector": {"provider": "strong"}})
        router = Router(cfg)
        self.assertIn("from-small", router.chat_role("executor", [Message("user", "x")]))
        self.assertIn("from-big", router.chat_role("reflector", [Message("user", "x")]))
        # supervisor inherits strategist which inherits executor when unset
        self.assertIn("from-small", router.chat_role("supervisor", [Message("user", "x")]))
        self.assertIn("from-small", router.chat_role("strategist", [Message("user", "x")]))

    def test_fallback_chain(self):
        cfg = self._cfg({
            "dead": {"type": "openai_compatible", "model": "x",
                     "base_url": "http://127.0.0.1:1/v1", "max_retries": 0},
            "alive": {"type": "mock", "model": "m", "lines": ["fallback-answer"]},
        }, roles={"executor": {"provider": "dead",
                               "fallback": [{"provider": "alive"}]}})
        router = Router(cfg)
        reply = router.chat_role("executor", [Message("user", "x")])
        self.assertEqual(reply, "fallback-answer")
        self.assertGreaterEqual(router.usage.failures, 1)

    def test_circuit_breaker_opens(self):
        cfg = self._cfg({
            "dead": {"type": "openai_compatible", "model": "x",
                     "base_url": "http://127.0.0.1:1/v1", "max_retries": 0},
            "alive": {"type": "mock", "model": "m", "lines": ["ok"] * 10},
        }, roles={"executor": {"provider": "dead",
                               "fallback": [{"provider": "alive"}]}})
        router = Router(cfg)
        for _ in range(3):
            self.assertEqual(router.chat_role("executor", [Message("user", "x")]), "ok")
        self.assertTrue(any(state == "DEAD"
                            for state in router.breaker_status().values()))

    def test_no_provider_error(self):
        router = Router(self._cfg({}))
        with self.assertRaises(LLMError):
            router.chat_role("executor", [Message("user", "x")])

    def test_race_backends(self):
        cfg = self._cfg({
            "a": {"type": "mock", "model": "a1", "lines": ["a"]},
            "b": {"type": "mock", "model": "b1", "lines": ["b"]},
        }, roles={"executor": {"provider": "a"}})
        cfg["solve"]["race_models"] = [{"provider": "a"}, {"provider": "b"}]
        router = Router(cfg)
        backends = router.race_backends()
        self.assertEqual(len(backends), 2)
        self.assertEqual([b.model for b in backends], ["a1", "b1"])


if __name__ == "__main__":
    unittest.main()
