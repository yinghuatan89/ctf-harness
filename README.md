# ctf-harness

> Speed-first, category-aware, multi-model AI harness for CTF competitions.
> 看不懂英文？[中文文档在这](README.zh-CN.md)

**ctf-harness** turns LLMs into a CTF solving team: a supervisor agent that
plans and dispatches specialist sub-agents, a zero-token speed pipeline that
solves easy challenges in seconds, category playbooks (web / pwn / crypto /
reverse / forensics / misc), 19 built-in attack recipes, CTFd integration and
a plugin system — all in pure Python with **zero required dependencies**.

Works with cloud vendors (OpenAI, DeepSeek, Kimi, Qwen, GLM, Anthropic, ...)
and local models (Ollama, vLLM, llama.cpp, LM Studio) — mix and match per
role.

---

## Why "speed-first"

The scoring function of a jeopardy CTF is *time-to-first-solve*. The harness
therefore spends intelligence only where it pays:

```
L0  zero-thought heuristics   base64/32/hex/zip/gzip/tar/caesar/xor/strings
    -> sub-second, zero tokens       (solves most beginner misc/crypto)
L1  recipe library            19 scripted attacks + your own recipes
    -> seconds, zero tokens          (RSA kit, SQLi bypass, PNG-LSB steg, ...)
L2  supervisor × specialists  LLM agents with tools, isolated contexts
    -> parallel hypotheses, first verified flag wins the race
L3  reflector replan          a stronger model reviews failures once
    -> only when L2 fails
```

Measured on the bundled selftest: L0/L1 stages solve their archetypes in
~0.1-2s with no API keys at all; the L2 race demo captures a flag in **0.8s**
end-to-end.

## Architecture

```
                 ┌────────────────────────────┐
                 │  Supervisor (planner LLM)  │  plan -> dispatch -> integrate
                 └──────┬─────────────────────┘
        ┌───────────────┼───────────────────┐
        ▼               ▼                   ▼
 ┌────────────┐  ┌────────────┐     ┌────────────┐
 │ Specialist │  │ Specialist │ ... │ Specialist │   isolated context per
 │ (recon)    │  │ (exploit)  │     │ (crypto)   │   sub-agent; messy work
 └─────┬──────┘  └─────┬──────┘     └─────┬──────┘   never pollutes the
       │ tools          │ tools          │ tools      supervisor prompt
       ▼                ▼                ▼
   shell / run_python / http / files / notes / submit_flag / report
       │
       └────► ResultBoard  (first VERIFIED flag stops every branch)
```

Each specialist runs in its own lane workspace, seeds from the shared
blackboard, and returns a distilled `report` (context quarantine — the
pattern that keeps multi-agent systems cheap). See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start

```bash
git clone https://github.com/<you>/ctf-harness && cd ctf-harness
python -m ctf_harness selftest     # offline proof, no API keys needed
```

Configure a model (copy & trim `examples/config.example.json` to `ctfh.json`):

```json
{
  "providers": {
    "deepseek": {"type": "openai_compatible", "base_url": "https://api.deepseek.com/v1",
                 "api_key": "env:DEEPSEEK_API_KEY", "model": "deepseek-chat"},
    "ollama":   {"type": "openai_compatible", "base_url": "http://localhost:11434/v1",
                 "api_key": "ollama", "model": "qwen2.5:14b"}
  },
  "roles": {"supervisor": {"provider": "deepseek"},
            "executor":   {"provider": "deepseek", "fallback": [{"provider": "ollama"}]},
            "reflector":  {"provider": "deepseek"}}
}
```

Solve things:

```bash
# a local challenge folder (auto-detects category)
ctfh solve ./chall --flag-format 'flag\{[^}]+\}'

# a web challenge with a flag verifier endpoint
ctfh solve --url http://chal.example.com/ --category web --scorer http://.../check

# a pwn challenge with a remote service
ctfh solve ./chall --remote 1.2.3.4:1337 --mode supervisor

# whole-competition batch mode against a CTFd instance
ctfh rush --ctfd https://ctf.example.com --token $CTFD_TOKEN --workers 3 --submit

# no API keys at all: L0+L1 only (still solves a surprising amount)
ctfh solve ./chall --no-llm

# pre-race warmup: which provider is fastest right now?
ctfh models --ping
ctfh doctor
```

Every solve produces `writeup.md` + a full `.ctfh/session.jsonl` replay
(regenerate with `ctfh report session.jsonl`).

## Model support (local + vendor)

| Type | Works with |
|---|---|
| `openai_compatible` | OpenAI, DeepSeek, Moonshot/Kimi, Qwen/DashScope, Zhipu GLM, SiliconFlow, xAI... **and** Ollama, vLLM, llama.cpp server, LM Studio |
| `anthropic` | Claude models via the Messages API |
| `mock` | scripted backends for tests/demos |

Roles (`supervisor` / `strategist` / `executor` / `reflector`) can point at
different providers, have per-role **fallback chains**, and a circuit breaker
marks a dying provider dead for 5 minutes instead of burning the clock.
Details: [docs/PROVIDERS.md](docs/PROVIDERS.md).

## Make it yours (extension surface)

| What | How |
|---|---|
| **Custom recipes without code** | drop JSON packs into `recipes.d/` — a declarative DSL with `{{url}}`, `{{file:...}}`, `{{capture:...}}` template variables |
| **Python plugins** | `plugins/*.py` — add tools, recipes, LLM providers and event hooks (`flag_found` → Feishu/WeCom/DingTalk webhooks) |
| **Knowledge base** | drop writeups/cheatsheets into `kb/` — relevant paragraphs get injected into agent prompts automatically |
| **Category playbooks** | every system prompt is a plain method — subclass or override; category auto-detection included |
| **Everything else** | `ctfh.json` (budgets, modes, lanes, timeouts) + CLI flags override all of it |

See [docs/RECIPES.md](docs/RECIPES.md) for the DSL spec and the built-in
recipe catalogue, and `examples/plugins/example_plugin.py`.

## Built-in recipe catalogue (L1)

**web**: leak-path probes (`robots/.git/.env/flag`), SQLi auth bypass,
SSTI fingerprint, JWT weak-secret replay, command-injection probe.
**crypto**: RSA attack kit (small-e cube root, Wiener, Fermat, common factor,
small factors, PEM/DER parsing), Vigenere (IC + chi-square), common-word
hash cracking.
**misc**: PNG LSB steg (pure-python decoder), PNG/JPEG trailing data,
zero-width unicode, Brainfuck interpreter, `.git` history mining,
known-plaintext XOR.
**forensics**: pcap flag/credential scan, magic-based file carving,
large-dump string hints.
**pwn/reverse**: ELF protections recon (PIE/NX/canary/RELRO, pure parser),
remote format-string probe, UPX unpacking.

## Safety & ethics

ctf-harness is for **authorized environments only**: CTF platforms, training
ranges, your own lab. Guardrails included: workspace jail for file
operations, a system-destructive command deny-list, scope-enforced HTTP
tooling (cloud metadata endpoints blocked), prompt-injection warnings, and
CTFd auto-submit is opt-in. It is not a sandbox — run untrusted binaries
inside a VM/container. Details: [SECURITY.md](SECURITY.md).

## Testing

```bash
python -m unittest discover -s tests   # 78 tests, offline, zero API keys
python -m ctf_harness selftest         # end-to-end: L0 -> L1 -> supervisor with mock LLMs
```

Both run in CI (Linux + Windows, Python 3.10-3.12).

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgements

Architecture patterns adapted from public multi-agent designs (supervisor
dispatch, role SOPs, sub-agent context quarantine) and re-implemented from
scratch for the CTF domain. No challenge-specific data or third-party code
is bundled.

> AI生成
