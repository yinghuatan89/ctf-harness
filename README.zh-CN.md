# ctf-harness（中文）

> 面向 CTF 竞赛的速度优先、分题型策略、多模型接入 AI Harness。English README [在这里](README.md)

**ctf-harness** 把大模型变成一支 CTF 解题战队：一个总控智能体（Supervisor）负责规划与分派，
多个专家子智能体（Specialist）并行执行；配合零 token 秒题流水线、六大题型 Playbook、
19 个内置攻击预案、CTFd 平台直连和插件系统 —— 纯 Python 实现，**零强制依赖**。

同时支持云端厂商（OpenAI、DeepSeek、Kimi、通义千问、智谱 GLM、Anthropic 等）与本地模型
（Ollama、vLLM、llama.cpp、LM Studio），可按角色混搭。

---

## 为什么是“速度优先”

Jeopardy 赛制的得分函数是**首解时间**。所以这个框架只在值得花智能的地方花：

```
L0  零思考启发式   base64/32/hex/zip/gzip/tar/凯撒/异或/strings 级联
    → 亚秒级、零 token        （新手题秒解，不烧任何模型调用）
L1  预案复放库     19 个脚本化攻击 + 你自定义的预案
    → 秒级、零 token          （RSA 套件、SQLi 绕过、PNG-LSB 隐写……）
L2  总控×专家     LLM 智能体 + 工具，上下文互相隔离
    → 并行假设赛道，首个验证通过的 flag 立刻全局终止
L3  反思重规划    强模型复盘一次失败过程
    → 只有 L2 失败才触发
```

内置自检实测：L0/L1 各自题型亚秒~秒级解决，L2 竞速演示端到端 **0.8 秒**拿旗。

## 架构

```
                 ┌────────────────────────────┐
                 │   总控 Supervisor（规划LLM） │  规划 → 分派 → 收编
                 └──────┬─────────────────────┘
        ┌───────────────┼───────────────────┐
        ▼               ▼                   ▼
 ┌────────────┐  ┌────────────┐     ┌────────────┐
 │ 侦察专家   │  │ 利用专家    │ ... │ 密码专家   │   每个子智能体独立上下文，
 │ (recon)    │  │ (exploit)  │     │ (crypto)   │   脏活烧自己的窗口，
 └─────┬──────┘  └─────┬──────┘     └─────┬──────┘   只回传蒸馏后的 report
       │ 工具           │ 工具           │ 工具
       ▼                ▼                ▼
   shell / run_python / http / files / notes / submit_flag / report
       │
       └────► ResultBoard（任一分支拿到已验证 flag → 全局秒停）
```

详细设计见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 快速开始

```bash
git clone https://github.com/<you>/ctf-harness && cd ctf-harness
python -m ctf_harness selftest     # 离线全链路自检，无需任何 API key
```

配置模型（复制 `examples/config.example.json` 裁剪成 `ctfh.json`）：

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

开始解题：

```bash
# 本地题目目录（题型自动侦测）
ctfh solve ./chall --flag-format 'flag\{[^}]+\}'

# Web 题 + flag 校验接口
ctfh solve --url http://chal.example.com/ --category web --scorer http://.../check

# Pwn 题 + 远程服务，总控-子智能体模式
ctfh solve ./chall --remote 1.2.3.4:1337 --mode supervisor

# 接 CTFd 整场批量打（并行 + 自动提交）
ctfh rush --ctfd https://ctf.example.com --token $CTFD_TOKEN --workers 3 --submit

# 完全不用 API key：只跑 L0+L1（能白嫖不少题）
ctfh solve ./chall --no-llm

# 赛前热身：看哪家模型现在最快
ctfh models --ping
ctfh doctor
```

每次解题都会产出 `writeup.md` 和完整的 `.ctfh/session.jsonl` 回放
（可用 `ctfh report session.jsonl` 重新生成复盘文档）。

## 模型接入（本地 + 厂商）

| 类型 | 适用 |
|---|---|
| `openai_compatible` | OpenAI、DeepSeek、Moonshot/Kimi、通义千问(兼容模式)、智谱 GLM、SiliconFlow 等 **以及** Ollama、vLLM、llama.cpp server、LM Studio 等本地服务 |
| `anthropic` | Claude 系列 Messages API |
| `mock` | 剧本化后端（测试/演示） |

四个角色（supervisor / strategist / executor / reflector）可分别指向不同
厂商和模型，支持**逐角色降级链**；连续失败自动熔断 5 分钟，比赛期间不烧表。
详见 [docs/PROVIDERS.md](docs/PROVIDERS.md)。

## 开放定制面

| 定制点 | 用法 |
|---|---|
| **免代码自定义预案** | `recipes.d/` 里丢 JSON——声明式 DSL，支持 `{{url}}`、`{{file:...}}`、`{{capture:...}}` 模板变量 |
| **Python 插件** | `plugins/*.py`——自定义工具、预案、模型后端、事件钩子（`flag_found` → 飞书/企微/钉钉 webhook） |
| **知识库** | `kb/` 里丢 writeup/速查表——按关键词相关性自动注入提示词，越攒越强 |
| **题型 Playbook** | 每类题的系统提示词都是纯方法——可继承可覆盖，题型自动侦测内置 |
| **其他一切** | `ctfh.json`（预算/模式/赛道数/超时）+ CLI 参数全量覆盖 |

DSL 规范与内置预案目录见 [docs/RECIPES.md](docs/RECIPES.md)，插件示例见
`examples/plugins/example_plugin.py`。

## 内置预案目录（L1）

- **web**：泄漏路径探测（robots/.git/.env/flag）、SQLi 登录绕过、SSTI 指纹、JWT 弱密钥复放、命令注入探测
- **crypto**：RSA 攻击套件（小指数开方、Wiener、费马分解、共因子、小因子、PEM/DER 解析）、维吉尼亚（重合指数+卡方）、常见口令哈希爆破
- **misc**：PNG LSB 隐写（纯 Python 解码器）、PNG/JPEG 尾随数据、零宽字符、Brainfuck 解释执行、.git 历史挖掘、已知明文异或
- **forensics**：pcap flag/凭据扫描、魔数文件雕刻、大体积转储字符串提示
- **pwn/reverse**：ELF 保护侦测（PIE/NX/Canary/RELRO 纯 Python 解析）、远程格式化字符串探测、UPX 脱壳

## 安全与合规

ctf-harness **仅限授权环境使用**：CTF 平台、训练靶场、你自己的实验室。
内置护栏：文件操作工作区监禁、系统破坏性命令黑名单、HTTP 工具范围强制
（云元数据端点封禁）、提示注入告警、CTFd 自动提交默认关闭。
它不是沙箱——跑不受信任的二进制请放到 VM/容器里。详见 [SECURITY.md](SECURITY.md)。

## 测试

```bash
python -m unittest discover -s tests   # 78 个测试，离线，零 API key
python -m ctf_harness selftest         # 端到端：L0 → L1 → 总控子智能体（mock 模型）
```

CI 在 Linux + Windows、Python 3.10-3.12 矩阵上跑全量。

## 许可

MIT —— 见 [LICENSE](LICENSE)。

## 致谢

架构模式参考了公开的多智能体设计（总控分派、角色 SOP、子智能体上下文隔离），
针对 CTF 场景从零重新实现。未捆绑任何题目数据或第三方代码。

> AI生成
