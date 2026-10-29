# Examples

Everything here is offline and safe (deliberately vulnerable training targets).

## challenges/ — bundled mini-challenges

| folder | archetype | solved by |
|---|---|---|
| `misc_base64/` | nested base64 blob | L0 heuristics |
| `crypto_caesar/` | Caesar shift note | L0 heuristics |
| `misc_xor/` | single-byte XOR binary | L0 heuristics |
| `crypto_rsa_small_e/` | RSA e=3, no padding, m^3<n | L1 `crypto.rsa_attacks` |
| `web_sqli/` | SQL string-concat login + hidden route + scorer | L1 `web.sqli_bypass` / L2 supervisor |

Run the web service:

```bash
python examples/challenges/web_sqli/server.py 8000
# then in another terminal:
ctfh solve --url http://127.0.0.1:8000/ --category web \
           --scorer http://127.0.0.1:8000/check --no-llm
```

`python -m ctf_harness selftest` exercises all of these automatically.

## mock/ — scripted LLM backends

`supervisor_script.jsonl` + `web_executor_script.jsonl` power the offline
supervisor end-to-end demo (used by selftest and CI). `{PORT}` tokens are
substituted at runtime.

## config.example.json

A fully commented provider/role/notify/solve config covering cloud vendors
(DeepSeek/Kimi/Qwen/GLM/OpenAI/Claude), local servers (Ollama/vLLM),
fallback chains, Feishu/WeCom/DingTalk webhooks.

## plugins/ & recipes.d/

Copy `plugins/example_plugin.py` into `./plugins/` and
`recipes.d/example_recipe.json` into `./recipes.d/` to see the extension
surface in action (`ctfh doctor` lists what got loaded).

> AI生成
