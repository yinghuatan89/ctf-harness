"""Web playbook: recon -> injection decision tree -> auth/logic -> RCE."""

from __future__ import annotations

from .base import Playbook, _desc_has, _file_heads, _has_ext


class WebPlaybook(Playbook):
    id = "web"
    title = "Web exploitation"

    def matches(self, challenge) -> float:
        if challenge.url:
            return 0.9
        if _has_ext(challenge, (".php", ".asp", ".aspx", ".jsp")):
            return 0.8
        if _file_heads(challenge) and any(
                head.startswith((b"<?php", b"<!DOCTYPE", b"<html", b"<!doctype"))
                for _p, head in _file_heads(challenge)):
            return 0.6
        if _desc_has(challenge, "web", "login", "http", "网站", "登录", "admin"):
            return 0.6
        return 0.0

    def seed_hypotheses(self, challenge) -> list[str]:
        base = (challenge.url or "the target").rstrip("/")
        return [
            f"Full content discovery first: GET {base}, {base}/robots.txt, "
            f"backup/source files, .git exposure; then attack the most "
            f"interesting endpoint found.",
            "If a login form exists: SQL authentication bypass, then look "
            "for admin functionality behind it.",
            "Blind injection probing on every parameter (SQLi/SSTI/cmd) with "
            "boolean and time-based differentials.",
        ]

    def system_prompt(self, challenge) -> str:
        return """## WEB METHODOLOGY
1. MAP: fetch index, robots.txt, sitemap.xml, /admin, backups (.bak/.old/.swp/~),
   .git/ or .svn/ exposure, exposed .env/config, JS files and API hints.
   Fingerprint the stack from headers/cookies: PHPSESSID -> PHP, JSESSIONID ->
   Java, session cookie with dots -> Python/Flask/Django.
2. PARAMETERS: enumerate every parameter from forms, JS and API responses.
   Probe each with break characters (' " \\ ; {{ < > ) and diff the responses.
3. INJECTION DECISION TREE:
   - SQLi: error-based (') -> boolean (' AND 1=1 vs ' AND 1=2) -> UNION
     (ORDER BY n to count columns, then nulls) -> extract data. Login bypass:
     ' OR 1=1-- -. WAF-ish? uni/**/on, mixed case, %00, double-URL encoding.
   - SSTI: {{7*7}} / ${7*7} / <%= 7*7 %> / {{7*'7'}} (=7777777 confirms
     Jinja2). Jinja2 RCE:
     {{config.__class__.__init__.__globals__['os'].popen('id').read()}}.
   - Command injection: ; id | `id` | $(id); bypass filters with ${IFS},
     %0a, base64-wrapped payloads.
   - LFI: php://filter/convert.base64-encode/resource=index.php,
     ../../etc/passwd, log poisoning, session inclusion, data:// wrappers.
   - Deserialization: PHP __wakeup/pop-chain gadgets, Java ysoserial
     CommonsCollections, Python pickle payloads, Ruby/Node equivalents.
4. AUTH/LOGIC: JWT alg=none or weak secret, IDOR (swap ids/uuids), race
   conditions on limited actions, password-reset flow flaws, mass assignment.
5. UPLOAD: extension case tricks (.phtml .php5), magic-byte prefixes,
   .htaccess re-enable tricks, polyglots (GIF89a + php).
6. SSRF: internal endpoints, localhost services, gopher/file schemes when
   the filter is weak. (Cloud metadata IPs are blocked by the harness guard.)
7. Finish fast: the flag is usually one injection away - do not gold-plate
   recon beyond two passes.
When writing scripts prefer run_python with urllib/socket so they replay in
the writeup.""" + ("" if not challenge.url else f"\nPrimary target: {challenge.url}")
