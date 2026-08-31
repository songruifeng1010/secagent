# SecAgentX · 企业安全智能体 v3.1.0

多智能体协同安全检测系统，支持 OpenAI / Anthropic 兼容协议及主流云端、本地模型，采用 **Agentic-RAG** 实现知识增强检索，并支持默认关闭、按需启用的自动威胁响应。

## 安装 CLI

推荐通过 Python 发行包安装；SecAgentX 的后端、预构建 Web、前端脚手架和知识库会一起进入 wheel，不需要用户再安装 Node 才能启动默认界面。

```bash
# 正式发布到 PyPI 后
pipx install secagentx

# 直接从仓库安装（仓库需包含已构建的 frontend/dist）
pipx install "git+https://github.com/songruifeng1010/secagent.git"

secagentx onboard
secagentx
secagentx dashboard
```

`npm` 只用于开发或定制 Vue 前端；CLI/后端的权威安装入口是 `pipx`/Python wheel，避免把 Python 服务伪装成 Node 包。

## 从 GitHub 克隆并运行

需要 Python 3.10 或更高版本。仓库已包含预构建 Web 界面，普通使用者不需要安装 Node.js。

```bash
git clone https://github.com/songruifeng1010/secagent.git
cd secagent
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows PowerShell 改用：.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .

# 首次配置真实模型，随后启动 Web 控制台
secagentx onboard
secagentx dashboard
```

只验证本地启动链路、不调用真实模型时，可先设置 `LLM_PROVIDER=mock`。Web 控制台默认仅监听 `127.0.0.1:8000`。

## Windows CMD 源码快速开始

```bat
cd /d C:\path\to\secagent
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pip install -e . --no-deps

rem 首次选择厂商、填写 API Key，并进行真实连通验证
secagentx onboard

rem 终端多轮对话；也可直接运行项目内置的 secagentx.cmd
secagentx
secagentx ask "分析这条安全告警"

rem 启动并自动打开 Web 控制台
secagentx dashboard
```

API Key 默认保存到 Windows 用户级 DPAPI 加密凭据库（安装可选 `keyring` 后也可使用系统 Keyring），不会写入项目或明文 JSON。只有 Provider 完成一次真实请求验证后才会成为活动配置。Web 控制台使用 HttpOnly Cookie、一次性 refresh token 轮换和 CSRF 校验，浏览器不再把令牌写入 localStorage；CLI/API 客户端继续支持 Bearer Token。

内置预设包括 DeepSeek、通义千问、OpenAI、Anthropic、Azure OpenAI、Gemini、OpenRouter、xAI、Kimi、Ollama 和 LM Studio；其他厂商可选择“自定义 OpenAI/Anthropic 兼容接口”，填写 API Base 与模型 ID。运行 `secagentx providers` 查看档案，`secagentx providers --use PROFILE_ID` 切换。

---

## 当前可用状态

| 维度 | 状态 | 备注 |
|------|:----:|------|
| 架构设计 | 可运行 | 多智能体协同 + 熔断器 + 审计日志；生产上线前仍需按环境压测和安全验收 |
| ML 模型 | 可选 | 需安装 `requirements-ml.txt`；仓库不附带预训练模型，指标不能替代生产数据验证 |
| 防火墙对接 | 适配器模式 | iptables / nftables / Cloud API 多种后端 |
| 告警接入 |  Webhook / Kafka / Syslog | 三种接入方式均已实现 |
| 数据库 |  PostgreSQL + SQLite | 环境变量切换，生产/开发灵活适配 |
| 认证安全 | JWT + RBAC + 脱敏 | 企业级安全体系 |
| 自动化 | 默认关闭 | 可配置自动闭环 / 封禁 / 升级 / 巡检，启用前应验证白名单和阈值 |
| Docker 部署 | 核心服务 | SecAgentX 应用 + PostgreSQL |
| 内置知识 | **1,674 NVD/CISA KEV + 365 MITRE + 14 合规 + 23 剧本** | 恶意 IP 缓存为可选下载数据，不是启动前置条件 |
| 自动化测试 | 后端 + 前端测试套件 | 含单元测试、集成测试、认证隔离和前端测试；以当前验收输出为准 |

---

## 生产部署（推荐 Docker）

```bash
# 在项目根目录显式设置强凭据；Compose 不提供默认密码。
export SECAGENTX_PASSWORD='replace-with-a-strong-password'
export SECAGENTX_JWT_SECRET='replace-with-a-random-secret-at-least-32-chars'
export POSTGRES_PASSWORD='replace-with-a-strong-random-postgres-password'
docker compose up -d
# 访问 http://localhost:8000
```

## 开发模式启动

```bash
# 核心运行时
pip install -r requirements.txt
# 开发、测试与 CI
pip install -r requirements-dev.txt
# 可选：向量化与机器学习能力
pip install -r requirements-ml.txt
# 可选：阿里云、腾讯云、AWS 防火墙适配器
pip install -r requirements-cloud.txt

# 首次启动前配置管理员凭据（示例值请替换）
export SECAGENTX_PASSWORD='replace-with-a-strong-password'

# 启动 API 服务
python3 -m backend.interface.api_server

# 启动前端（新终端）
cd frontend && npm ci && npm run dev
```

### 统一 CLI 与 Web 启动

CLI 与 Web 服务使用同一套 Agent、认证隔离和知识库代码，可交互运行，也可输出机器可读 JSON：

```bash
# 首次配置（会验证 Provider 后再保存）
secagentx onboard

# 交互模式
secagentx

# 一次性查询
secagentx ask "什么是 SQL 注入？"

# 自动化脚本/CI 使用
secagentx ask "分析 45.33.32.156" --json

# 启动 Web；默认只监听 127.0.0.1
secagentx dashboard

# 诊断配置，--live 会发起一次真实模型请求
secagentx doctor
secagentx doctor --live
```

未配置真实 LLM Key 时可显式设置 `LLM_PROVIDER=mock` 验证启动链路；此模式只用于开发，不代表真实研判能力。Windows PowerShell 使用 `$env:LLM_PROVIDER='mock'`，Linux/macOS 使用 `export LLM_PROVIDER=mock`。

### 搭建自己的前端

```bat
secagentx ui init C:\work\my-secagentx-ui
cd /d C:\work\my-secagentx-ui
npm ci
npm run dev

rem 构建后让 SecAgentX 托管自定义界面
npm run build
secagentx dashboard --ui C:\work\my-secagentx-ui\dist
```

`ui init` 不复制 `node_modules`、`dist` 或覆盖非空目录。监听非回环地址时必须显式添加 `--allow-remote`，并在企业环境配置 TLS 反向代理、防火墙和 `SECAGENTX_CORS_ORIGINS`。

### 验证

```bash
python -m compileall -q backend tests scripts
pytest -m "not slow" --timeout=60
python scripts/quality/knowledge_health.py --strict --score
cd frontend && npm test && npm run build
```

真实威胁 IP 缓存不是核心启动前置条件。网络可用时运行 `python scripts/update_threat_ips.py` 获取；若所有远程源失败，脚本会返回失败并保留已有缓存，不会写入空库。

## 生产数据原则

事件、资产和处置记录只来自 API/Webhook、日志接入器或数据库中的实际记录。空数据库会在 Web 中显示空状态，不会自动注入演示告警。MITRE ATT&CK 和 NVD/CISA KEV 为带来源的公开知识快照，合规/处置内容为静态参考指南，都不代表企业的实时业务数据。威胁情报未配置外部 API 时会明确标注覆盖不足。

---

## 架构

```
                         用户 (Web/CLI/Webhook)
                                │
                   ┌────────────┴────────────┐
     │   TrueReAct 循环调度引擎   │  ← 活动模型 Provider
                   └────────────┬────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │           │                 │             │
     Analyst        Intel          Responder    Knowledge
   (统一 Provider) (统一 Provider) (统一 Provider) (Provider+RAG)
          │           │                 │             │
          └───────────┴─────────────────┴─────────────┘
                                │
                     ┌──────────┴──────────┐
                     │  Tools (6 个安全工具) │
                     │ threat_intel /       │ → iptables/Cloud API
                     │ firewall / geoip /   │
                     │ cve_search /         │
                     │ log_analyzer /       │
                     │ alert_filter         │
                     └──────────┬──────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
    PostgreSQL/SQLite      ChromaDB向量库       Docker Compose
    (事件/用户/日志)        (可选语义RAG)       (应用 + PostgreSQL)
```

---

## 核心能力

| 能力 | 描述 |
|------|------|
|  **多智能体协同** | Analyst / Intel / Responder / Knowledge / AlertFilter / Summary / Classifier 7 个 Agent |
|  **多厂商 LLM** | OpenAI / Anthropic 兼容协议，云端和本地模型统一配置，保留旧版 Fallback 兼容 |
|  **Agentic-RAG** | 知识增强检索，MITRE ATT&CK 全覆盖（365 技术 / 15 战术） |
|  **威胁情报** | VirusTotal / AbuseIPDB / OTX 可选多源验证；缺 Key 时使用本地知识和离线适配器 |
|  **ML 威胁检测** | 可选安装；训练与评估代码可用，实际效果需使用部署环境数据重新验证 |
|  **防火墙封禁** | 默认禁用；显式配置 iptables / nftables / Cloud API，Mock 仅测试 |
|  **自动处置** | 自动闭环 / 封禁 / 升级 / 巡检 / 数据保留，默认关闭 |
|  **可解释风险评分** | 行为证据 / 威胁情报 / IP真实性 / 历史信誉 四维加减分，最终分数 + 危级，逐规则可审计 |
|  **告警接入** | Webhook / Kafka / Syslog 三种方式 |
|  **企业安全** | JWT 认证 + RBAC 权限 + 熔断器 + 审计日志 + 限流 |
|  **跨区域联邦** | 多区域事件/IP 同步，mesh 拓扑 |

---

## 内置知识与可选数据

| 数据域 | 数据量 | 来源 | 真实性 |
|--------|:------:|------|:------:|
| 恶意 IP | 可选下载 | FireHOL / Darklist / Blocklist.de 等公开情报源 | 当前仓库不内置缓存，运行更新脚本获取 |
| MITRE ATT&CK 技术 | **365 个** | MITRE 官方 CTI | 官方数据 |
| MITRE ATT&CK 战术 | **15 个** | MITRE 官方 CTI |  官方数据 |
| NVD/CISA KEV | **1,674 条** (595 CRITICAL / 871 HIGH / 200 MEDIUM / 8 LOW) | NVD CVE API 2.0 | 官方可追溯快照 |
| 合规法规 | **14 项** | 等保2.0/网络安全法/GDPR/个保法等 | 真实法规 |
| 应急响应剧本 | **23 个** | 真实攻击场景（SSH爆破/勒索/C2/钓鱼等） | 真实场景 |
| APT 威胁组织 | **34 个** | 公开威胁情报 | 真实组织 |
| 恶意软件 | **47 个** | 公开威胁情报 | 真实恶意软件 |

### 数据更新命令

```bash
# 单独更新威胁 IP
python3 scripts/update_threat_ips.py
```

---

## API 端点一览（51 个 HTTP/WebSocket 路由）

| 分类 | 端点 | 说明 |
|------|------|------|
| **认证** | `/api/auth/login`, `/api/auth/refresh` | JWT 登录/刷新 |
| **健康** | `/api/health`, `/api/stats`, `/api/metrics` | 系统状态 |
| **事件** | `/api/events`, `/api/events/{id}` | 安全事件 CRUD |
| **MITRE** | `/api/mitre/search`, `/api/mitre/technique/{id}`, `/api/mitre/kill-chain`, `/api/mitre/attack-flow` | ATT&CK 知识库 |
| **CVE** | `/api/cve/search`, `/api/cve/{id}`, `/api/cve/by-mitre/{tech_id}` | 漏洞库 |
| **合规** | `/api/compliance/search`, `/api/compliance/{name}` | 法规库 |
| **剧本** | `/api/remediation/search`, `/api/remediation/{scenario}` | 应急响应 |
| **Agent** | `/api/agents`, `/api/agents/runtime` | 智能体运行时 |
| **联邦** | `/api/federation/status`, `/api/federation/events`, `/api/federation/blacklist` | 跨区域同步 |
| **用户** | `/api/users`, `/api/users/{username}`, `/api/users/me` | 用户管理 |
| **WebSocket** | `/ws/chat` | 实时对话 |

---

## 项目结构

```
secagentx/
├── backend/
│   ├── agents/           # 7 个安全 Agent 实现
│   ├── orchestrator/     # TrueReAct 循环总调度
│   ├── tools/            # 6 个注册安全工具（含多种防火墙后端）
│   ├── llm/              # 多厂商 LLM 兼容层（OpenAI / Anthropic / Mock）
│   ├── ml_model/         # 可选 ML 训练与检测流水线
│   ├── knowledge/        # MITRE / CVE / 合规 / 剧本 / 威胁情报
│   ├── storage/          # PostgreSQL/SQLite + Chroma 向量库
│   ├── security/         # 认证/脱敏/熔断器/审计/限流
│   ├── federation/       # 跨区域联邦同步
│   └── interface/        # CLI + FastAPI + WebSocket
├── frontend/             # Vue 3 + Naive UI + ECharts (10 视图)
├── knowledge_data/       # 知识库数据 (1,674 KEV / 365 MITRE / 14 合规 / 23 剧本)
├── Dockerfile            # 前端构建 + Python 运行时多阶段镜像
├── docker-compose.yml    # SecAgentX + PostgreSQL 生产部署
├── scripts/              # 运维/数据注入脚本
├── tests/                # 后端单元与集成测试
└── data/                 # 运行时 SQLite 数据库与可选缓存
```

---

## 版本历史

| 版本 | 日期 | 说明 |
|:----:|:----:|------|
| v3.1.0 | 2026-08-23 | HttpOnly Web 会话/CSRF、bcrypt 迁移、AI 金标准评测、数据完整性与 CI 安全门禁 |
| v3.0.0 | 2026-08-22 | 统一 CLI/onboarding/dashboard、自定义 UI、多厂商 Provider、系统安全凭据与企业默认边界 |
| v2.1.0 | 2026-07-23 | ML 训练评估流水线 / 前后端路由联调 / 前端测试 |
| v2.0.0 | 2026-07-08 | 多 Agent + TrueReAct + Docker Compose |
| v1.1 | 2026-06-15 | 单 Agent + 基础 API + 前端初版 |

---

## 许可证

本项目采用 [MIT License](LICENSE)。
