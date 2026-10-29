"""Webhook notifications for flag events.

Configure in ``ctfh.json``::

    "notify": {
      "flag_found": [
        {"type": "feishu", "url": "https://open.feishu.cn/..."},
        {"type": "wecom",  "url": "https://qyapi.weixin.qq.com/..."},
        {"type": "dingtalk", "url": "https://oapi.dingtalk.com/..."},
        {"type": "generic", "url": "https://your.server/hook",
         "template": {"event": "flag", "name": "{name}", "flag": "{flag}"}}
      ]
    }

Notes:
* notification URLs are user-configured and intentionally bypass the
  challenge-scope guard;
* notifications are best-effort: failures never interrupt a solve.
"""

from __future__ import annotations

import json
import urllib.request

_TEXT_FORMATS = ("feishu", "wecom", "dingtalk")


def _build_body(hook: dict, payload: dict) -> dict:
    hook_type = str(hook.get("type") or "generic").lower()
    text = f"[ctf-harness] FLAG on {payload.get('name', '?')}: {payload.get('flag', '?')} (via {payload.get('via', '?')})"
    if hook_type in _TEXT_FORMATS:
        if hook_type == "feishu":
            return {"msg_type": "text", "content": {"text": text}}
        return {"msg_type": "text", "text": {"content": text}}
    template = hook.get("template")
    if isinstance(template, dict):
        rendered = {}
        for key, value in template.items():
            if isinstance(value, str):
                for name, sub in payload.items():
                    value = value.replace("{" + str(name) + "}", str(sub))
                rendered[key] = value
            else:
                rendered[key] = value
        return rendered
    return {"event": "flag_found", **payload}


def notify(cfg: dict, event: str, payload: dict) -> list[str]:
    """Fire every webhook configured for ``event``; returns error strings."""
    errors: list[str] = []
    hooks = (cfg.get("notify") or {}).get(event) or []
    if not isinstance(hooks, list):
        return errors
    for hook in hooks:
        url = hook.get("url")
        if not url:
            continue
        body = _build_body(hook, payload)
        try:
            request = urllib.request.Request(
                url, data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(request, timeout=10) as resp:
                resp.read()
        except Exception as exc:  # noqa: BLE001 - never break solving
            errors.append(f"{str(url)[:60]}: {exc}")
    return errors
