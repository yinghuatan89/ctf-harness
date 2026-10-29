"""http tool: scope-enforced HTTP client for web challenges.

Redirects are followed manually (max 4 hops) so every hop passes the guard.
Error responses are returned as observations (they are signal, not failures).
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from .base import Tool, ToolContext, ToolError, ToolResult, bounded_number

MAX_BODY_BYTES = 512 * 1024
MAX_HOPS = 4


def _add_params(url: str, params: dict | None) -> str:
    if not params:
        return url
    query = urllib.parse.urlencode({str(k): str(v) for k, v in params.items()})
    separator = "&" if urllib.parse.urlparse(url).query else "?"
    return url + separator + query


def _build_body(method: str, headers: dict, data, json_body):
    request_headers = {str(k): str(v) for k, v in headers.items()}
    if json_body is not None:
        import json
        body = json.dumps(json_body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    elif isinstance(data, dict):
        body = urllib.parse.urlencode({str(k): str(v) for k, v in data.items()}).encode()
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif isinstance(data, str):
        body = data.encode("utf-8", "replace")
    else:
        body = None
    if body is not None and method in ("GET", "HEAD"):
        method = "POST"  # urllib requires a body-carrying method
    return method, request_headers, body


class HttpTool(Tool):
    name = "http"
    description = ("Send an HTTP request to the challenge target (scope-enforced, "
                    "max 4 redirect hops, error pages returned as observations).")
    args_help = ('{"method": "GET", "url": "http://host/path", "headers": {}, '
                 '"data": {"k": "v"} or "raw", "json": {}, "params": {}, "timeout": 20, '
                 '"follow_redirects": true}')

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = args.get("url")
        if not isinstance(url, str) or not url.strip():
            raise ToolError("args.url (string) is required")
        method = str(args.get("method") or "GET").upper()
        timeout = bounded_number(args.get("timeout"), 20, 1, 60)
        headers = args.get("headers") or {}
        if not isinstance(headers, dict):
            raise ToolError("args.headers must be an object")
        params = args.get("params") if isinstance(args.get("params"), dict) else None
        json_body = args.get("json") if args.get("json") is not None else None
        if json_body is not None and not isinstance(json_body, dict):
            raise ToolError("args.json must be an object")
        data = args.get("data")
        follow = bool(args.get("follow_redirects", True))

        current_url = _add_params(url, params)
        current_method = method
        for _hop in range(MAX_HOPS):
            ctx.guard.check_url(current_url)
            hop_method, hop_headers, hop_body = _build_body(
                current_method, headers, data if _hop == 0 else None, json_body if _hop == 0 else None)
            request = urllib.request.Request(
                current_url, data=hop_body, headers=hop_headers, method=hop_method)
            try:
                with urllib.request.urlopen(request, timeout=timeout) as resp:
                    status, reason = resp.status, resp.reason or ""
                    resp_headers = resp.headers
                    body = resp.read(MAX_BODY_BYTES)
            except urllib.error.HTTPError as exc:
                status = exc.code
                reason = getattr(exc, "reason", "") or ""
                resp_headers = exc.headers or {}
                try:
                    body = exc.read(MAX_BODY_BYTES)
                except Exception:  # noqa: BLE001
                    body = b""
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                return ToolResult(False, f"ERROR: request failed: {exc}")

            if status in (301, 302, 303, 307, 308) and follow:
                location = resp_headers.get("Location")
                if location:
                    current_url = urllib.parse.urljoin(current_url, location)
                    if status == 303:
                        current_method = "GET"
                    continue
            break

        header_lines = "\n".join(
            f"{key}: {value}" for key, value in list(resp_headers.items())[:25])
        head = f"HTTP {status} {reason}\n{header_lines}"
        binary = b"\x00" in body[:256]
        if binary:
            body_note = f"--- body is binary ({len(body)} bytes) ---\nfirst 64 bytes hex: {body[:64].hex()}"
        else:
            body_note = (f"--- body ({len(body)} bytes) ---\n"
                         + body.decode("utf-8", "replace"))
        output = head + "\n" + body_note
        return ToolResult(ok=(status < 400), output=output)
