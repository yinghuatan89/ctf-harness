# Recipes (L1): built-ins + writing your own

Recipes are scripted, deterministic attacks that run *before* any LLM token
is spent. They return flag **findings** (verified centrally) and/or
**blackboard notes** that seed the L2 agents with recon.

## Built-in catalogue (19)

| id | category | what it does |
|---|---|---|
| `web.low_hanging` | web | probes robots/.git/.env/flag/backup paths |
| `web.sqli_bypass` | web | parses the login form, fires classic auth-bypass payloads |
| `web.ssti_probe` | web | `{{7*7}}` family fingerprints per param |
| `web.jwt_probe` | web | decodes JWTs, flags alg=none, replays common HMAC secrets |
| `web.cmd_injection_probe` | web | `;id` family via common param names |
| `crypto.rsa_attacks` | crypto | small-e cube root, Wiener, Fermat, common factor, small factors, PEM/DER |
| `crypto.vigenere` | crypto | IC key-length detection + chi-square solving |
| `crypto.hash_crack` | crypto | common wordlist vs md5/sha1/sha256/sha512 (incl. `flag{word}` wraps) |
| `misc.steg_probe` | misc | pure-python PNG LSB decode, PNG/JPEG trailing data, text chunks |
| `misc.zero_width` | misc | U+200B/200C binary decode |
| `misc.brainfuck` | misc | embedded BF interpreter |
| `misc.git_mining` | misc | `git log -p --all`, stash, refs scan |
| `misc.known_plaintext_xor` | misc | derives the key from an assumed `flag{` prefix |
| `forensics.pcap_scan` | forensics | flags/creds/URIs/basic-auth in captures |
| `forensics.file_carve` | forensics | carves PNG/JPEG/ZIP/PDF/SQLite blobs from carriers |
| `forensics.memory_hints` | forensics | sampled string mining of large dumps |
| `pwn.elf_recon` | pwn/rev | PIE/NX/canary/RELRO + suspicious symbol notes |
| `pwn.fmt_probe` | pwn | sends `%p` payloads to the remote, reports echo offset |
| `pwn.upx_unpack` | pwn/rev | `upx -d` then re-scan strings |

## Declarative recipes (no code)

Drop `*.json` into `recipes.d/` (repo dir) or `~/.ctfh/recipes.d/`:

```json
{
  "id": "user.admin_backup_probe",
  "title": "Probe the admin backup endpoint",
  "category": "web",
  "requires": {"url": true, "content_regex": "backup"},
  "steps": [
    {"tool": "http",
     "args": {"method": "GET", "url": "{{url}}/admin/backup.zip"},
     "capture": {"zip_head": "PK\\x03\\x04"}},
    {"tool": "run_python",
     "code": "import zipfile;print(zipfile.ZipFile('dl.zip').namelist())"}
  ]
}
```

Schema:
- `id`, `title` (required); `category`/`categories` optional gate
- `requires`: `url` / `remote` bool, `content_regex` on description+files,
  `files`: [name regexes]
- `steps`: up to 12; each = one tool call. Use `tool: http|shell|run_python`
  with `args`/`code`/`cmd`, or pass a bare URL string.
- per-step `capture: {name: regex}` extracts groups from that step's output
  into a `{{capture:name}}` variable; `set: {name: value}` stores literals.

Template variables: `{{url}}`, `{{remote}}`, `{{flag_format}}`,
`{{name}}`/`{{challenge_name}}`, `{{file:relative/path}}` (first 64 KB),
`{{capture:name}}`, `{{var:name}}`. Every step output is scanned for the
flag format automatically.

## Python recipes (full power)

Either use the plugin API (`plugins/my.py`):

```python
from ctf_harness.solver.recipes.base import Recipe

class MyRecipe(Recipe):
    id = "user.my_recipe"
    title = "Attack the widget protocol"

    def match(self, challenge):
        return challenge.remote is not None

    def run(self, rc):
        result = rc.dispatch("run_python", code="print('hi')")
        return rc.scan(result.output)

def register(reg):
    reg.register_recipe(MyRecipe(MyRecipe.id, MyRecipe.title, (), ""))
```

...or extend the built-in factories in
`ctf_harness/solver/recipes/*.py` directly when contributing upstream.

> AI生成
