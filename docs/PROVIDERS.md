# Model providers & roles

ctf-harness talks to any OpenAI-compatible chat endpoint plus Anthropic,
so it covers both cloud vendors and local servers with one implementation.

## Cloud vendors (`type: openai_compatible`)

| Vendor | base_url | notes |
|---|---|---|
| DeepSeek | `https://api.deepseek.com/v1` | cheap + strong reasoning, good default executor |
| Moonshot/Kimi | `https://api.moonshot.cn/v1` | long context |
| Qwen (DashScope) | `https://dashscope.aliyuncs.com/compatible-mode/v1` | compatible mode |
| Zhipu GLM | `https://open.bigmodel.cn/api/paas/v4` | |
| OpenAI | `https://api.openai.com/v1` | |
| SiliconFlow / others | any `/v1` endpoint | |

## Local models (`type: openai_compatible`)

| Server | base_url |
|---|---|
| Ollama | `http://localhost:11434/v1` (`api_key: "ollama"`) |
| vLLM | `http://localhost:8000/v1` |
| llama.cpp server | `http://localhost:8080/v1` |
| LM Studio | `http://localhost:1234/v1` |

## Anthropic (`type: anthropic`)

```json
"claude": {"type": "anthropic", "api_key": "env:ANTHROPIC_API_KEY",
           "model": "claude-sonnet-4-20250514"}
```

## Roles, fallbacks, breaker

- `supervisor` — plans & dispatches (falls back to `strategist` → `executor` config)
- `strategist` — hypothesis generation (race/single mode)
- `executor` — lane/specialist tool loops
- `reflector` — stuck-loop reviews and the L3 final replan

Each role accepts `provider`, optional `model` override and a `fallback`
chain. After 3 consecutive failures a backend is circuit-broken for 5 min.
`ctfh models --ping` measures live latency for a pre-race lineup check.

```json
"roles": {
  "supervisor": {"provider": "deepseek", "fallback": [{"provider": "ollama"}]},
  "executor":   {"provider": "deepseek", "fallback": [{"provider": "ollama"}]},
  "reflector":  {"provider": "claude",   "fallback": [{"provider": "deepseek"}]}
}
```

Environment overrides: `CTFH_EXECUTOR_PROVIDER`, `CTFH_EXECUTOR_MODEL`, ...
Secrets: use `"api_key": "env:MY_KEY"` so keys never live in config files.

## Token budget

`Router.usage` keeps a chars/4 estimate of prompt/completion tokens and
request counts; it is included in every solve result and in the session log.
Use `solve.time_budget_s` as the primary cost control.

## Race line-up (`solve.race_models`)

In `--mode race`, lanes round-robin across this list — e.g. one local model
and one cloud model attack the same hypothesis set simultaneously and the
first verified flag wins:

```json
"solve": {"mode": "race", "lanes": 2,
          "race_models": [{"provider": "ollama"}, {"provider": "deepseek"}]}
```

> AI生成
