# Security policy & scope

## Authorized use only

ctf-harness is a competition/training tool. Use it **only** against:

* official CTF platforms and their challenge infrastructure,
* deliberately vulnerable training environments,
* systems you own or are explicitly authorized to test.

Attacking systems without authorization is illegal in most jurisdictions.
CTFd auto-submission is **opt-in** (`--submit`) for the same reason.

## Built-in guardrails

| Layer | Mechanism |
|---|---|
| file ops | all reads/writes are jailed to the per-challenge workspace (realpath check) |
| shell | deny-list of system-destructive patterns (`rm -rf /`, mkfs, fork bombs, raw device writes, power control, `format x:`, cloud metadata endpoints) |
| http tool | challenge-scope enforcement (declared hosts + loopback), http/https only, max 4 redirect hops each re-checked, metadata IPs always blocked |
| flags | scorer verification when available, else strict flag-format regex; deduplicated, capped attempts |
| prompts | challenge content is declared to be DATA, not instructions (prompt-injection hardening) |
| secrets | `env:` indirection keeps API keys out of config files; keys are never logged |
| webhooks | notification URLs are user-configured and bypass the scope guard by design — point them only at your own bots |

## What this is NOT

The guard is a seatbelt, **not a sandbox**:

* shell commands run with your user privileges on your workstation;
* `run_python` executes generated code in a subprocess;
* binaries from a CTF may be hostile.

For untrusted binaries, run the harness inside a VM or container (the
workspace layout makes this trivial: mount the challenge dir and go).

## Plugins are code

Anything in `plugins/` runs with your privileges at startup. Only install
plugins you trust (same trust model as pytest/conda plugins).

## Data flow

Local processing first: recon, L0/L1 and flag verification never leave your
machine. Prompt content (recon text, tool outputs) goes **only** to the LLM
endpoints you configure in `ctfh.json`. Notification webhooks receive only
challenge name/flag/via. No telemetry is collected by this project.

## Reporting

Found a security issue in the harness itself? Please open a private GitHub
Security Advisory instead of a public issue.

> AI生成
