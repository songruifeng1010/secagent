# SecAgentX · 本机安全智能体 v4.0.0

多智能体协同安全检测系统，支持 OpenAI / Anthropic 兼容协议及主流云端、本地模型，采用 **Agentic-RAG** 实现知识增强检索，并支持默认关闭、按需启用的自动威胁响应。

## 安装 CLI

推荐通过 Python 发行包安装；SecAgentX 的后端、预构建 Web、前端脚手架和知识库会一起进入 wheel，不需要用户再安装 Node 才能启动默认界面。

```bash
# 正式发布到 PyPI 后
pipx install secagentx

# 也可使用 uv 管理全局 CLI
uv tool install secagentx

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
python -m pip install .

# 首次配置真实模型，随后启动 Web 控制台
secagentx onboard
secagentx dashboard
```

`git clone` 是 Git 与网络连接的步骤，尚未进入 SecAgentX 的构建流程。若出现 `Failed to connect to github.com:443`，请先检查网络、代理或防火墙；已在 GitHub 账户配置 SSH Key 的用户可改用 GitHub 的 443 SSH 入口：

```bash
git clone ssh://git@ssh.github.com:443/songruifeng1010/secagent.git
```

普通使用者应使用 `python -m pip install .`，它会构建并安装项目；只有需要修改源代码时才使用 `python -m pip install -e .`。从 GitHub 直接安装也可使用 `pipx install "git+https://github.com/songruifeng1010/secagent.git"`，但同样依赖本机能访问 GitHub 和 Python 软件源。

网络受限时，可下载已发布的 Release wheel 后本地安装：`pipx install ./secagentx-4.0.0-py3-none-any.whl`。仅有项目 wheel 时仍需联网安装依赖。

完整离线包应在与目标机器相同的操作系统、CPU 架构和 Python 版本下准备。联网机器执行 `python -m pip download --only-binary=:all: -d wheelhouse ./secagentx-4.0.0-py3-none-any.whl`，复制整个 wheelhouse 后执行下面的离线脚本。目录中只保留一个 SecAgentX 版本；目标机器需先安装 Python 和 pipx。可以使用本地构建的 wheel，不以项目已发布到 PyPI 为前提。

项目也提供离线安装脚本：Windows PowerShell 执行 `powershell -ExecutionPolicy Bypass -File scripts/install_offline.ps1`，Linux/macOS 执行 `bash scripts/install_offline.sh`。脚本只从本地 `wheelhouse/` 安装，不会访问 GitHub 或 PyPI。

只验证本地启动链路、不调用真实模型时，可先设置 `LLM_PROVIDER=mock`。Web 控制台默认仅监听 `127.0.0.1:8000`。

## Windows CMD 源码快速开始

```bat
cd /d C:\path\to\secagent
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install .

rem 首次选择厂商、填写 API Key，并进行真实连通验证
secagentx onboard

rem 终端多轮对话；也可直接运行项目内置的 secagentx.cmd
secagentx chat
secagentx ask "分析这条安全告警"

rem 启动并自动打开 Web 控制台
secagentx dashboard
```

`secagentx chat` 是纯终端交互界面：Rich 实时展示执行状态与流式回答，完整日志写入文件。普通知识问答直接显示 Markdown 正文，事件研判使用报告面板。`secagentx ask "问题" --json` 保持单行 JSON 输出。

使用 `/new` 新建会话、`/history` 查看会话 ID、`/resume ID` 恢复会话、`/model` 查看模型、`/export 文件.md` 导出会话（不会覆盖已有文件）。方向键 ↑/↓ 浏览本次终端输入历史，输入 `/` 后按 Tab 补全命令；输入历史只存内存，不额外写入历史文件。分析过程中按 Ctrl+C 取消并返回输入，输入时按 Ctrl+C 退出。多行输入用三反引号开始和结束，在多行模式按 Ctrl+C 会丢弃草稿而不发送。非交互管道、简易终端或旧环境未安装 `prompt-toolkit` 时自动退回普通输入。

API Key 默认保存到 Windows 用户级 DPAPI 加密凭据库（安装可选 `keyring` 后也可使用系统 Keyring），不会写入项目或明文 JSON。只有 Provider 完成一次真实请求验证后才会成为活动配置。Web 控制台不需要账户、密码或令牌，且仅允许本机访问。

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
| 访问边界 | 仅本机回环监听 + 脱敏 | 无登录模式不对远程网络开放 |
| 自动化 | 默认关闭 | 可配置自动闭环 / 封禁 / 升级 / 巡检，启用前应验证白名单和阈值 |
| Docker 部署 | 核心服务 | SecAgentX 应用 + PostgreSQL |
| 内置知识 | **1,674 NVD/CISA KEV + 365 MITRE + 14 合规 + 23 剧本** | 恶意 IP 缓存为可选下载数据，不是启动前置条件 |
| 自动化测试 | 后端 + 前端测试套件 | 含单元测试、集成测试和前端测试；以当前验收输出为准 |

---

## 生产部署（推荐 Docker）

```bash
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

# 启动 API 服务
python3 -m backend.interface.api_server

# 启动前端（新终端）
cd frontend && npm ci && npm run dev
```

### 统一 CLI 与 Web 启动

CLI 与 Web 服务使用同一套 Agent 和知识库代码，可交互运行，也可输出机器可读 JSON。Web 仅监听本机回环地址，无账户、密码或令牌认证：

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

### GitHub 发布前检查

训练数据、离线模型和本地测试产物不会随源码发布。提交或打标签前，在项目根目录执行：

```bash
python scripts/release_preflight.py
```

该检查只扫描已进入 Git 暂存区的文件，不会删除本地数据；如果误将大文件、数据集、模型或环境变量文件加入暂存区，会在推送前直接失败。

### ML 模型训练与部署状态

仓库提供可复现的 ML 训练流水线，但不内置数据集或预训练模型。当前提供 NSL-KDD、UNSW-NB15、CSE-CIC-IDS2018 三个适配器；数据文件布局和字段要求见 [dataset/README.md](dataset/README.md)。安装 `requirements-ml.txt` 后按数据集运行：

```bash
python scripts/retrain_model.py --algo xgboost --version v1
python scripts/retrain_model.py --dataset unsw-nb15 --algo xgboost --version v1
python scripts/retrain_model.py --dataset cic-ids-2018 --algo xgboost --version v1
```

CSE-CIC-IDS2018 约 820 万条记录，内存受限环境建议首次验证使用 `--max-rows 300000 --sampling stratified --no-tune --no-calibrate`；分层抽样会覆盖整个训练/测试文件，而不是只读取文件开头。该命令仍属于“受限样本”实验，生产评估应在更大内存机器上执行全量训练。

训练流程严格使用各数据集准备好的训练/测试划分、保存模型与特征预处理元数据，并生成评估报告。运行时不会生成合成数据，也不会在找不到模型时自动训练；可通过 `GET /api/ml/status` 或 `GET /api/ml/models` 查看各数据集模型是否已部署。当前仓库没有附带 `.joblib` 模型文件，示例指标仅是历史基准，不能视为本环境实测结果。

运行时还会执行模型质量门禁（F1≥0.50、Recall≥0.20、ROC-AUC≥0.70，训练/测试准确率差距≤0.15）。训练文件成功生成但未达到门槛的模型仍会保留在报告中供审计，不会被自动加载。

### RAG 索引状态

知识库原文随仓库提供，ChromaDB 向量索引需要单独构建。使用 `python scripts/data_pipeline/embed_knowledge.py --status` 查看本地索引，也可调用 `GET /api/knowledge/index/status` 获取机器可读状态；索引不可用时会降级到关键词检索。

### 研判会话工作区

PC 控制台将一次研判作为可恢复的本地会话管理。会话标题由首条提问自动生成，也可手动重命名；支持搜索、按时间分组、置顶、删除及导出 Markdown。删除会同时移除该会话的消息和关联执行轨迹，无法恢复。

默认对话区只显示提问、AI 答复和最终研判报告，避免工具调用与 Agent 状态淹没结论。需要审计时，点击工作区右上角的“查看过程”，即可展开保留的执行时间线；最终报告可在“快速分析”和“专家报告”之间切换，并可复制或导出。

回答会按场景自动选择展示形式：概念、定义和原理类问题（例如“什么是 SQLite 注入？”）直接输出纯文本，不显示风险评分框；IP、域名等 IOC 查询显示情报摘要；漏洞、攻击和告警进入安全研判报告；应急处置显示处置报告；配置、加固和合规问题显示操作清单。后端事件中的 `response_mode` 是这一展示契约，CLI/API 使用者也可据此决定自己的渲染方式。

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

`ui init` 不复制 `node_modules`、`dist` 或覆盖非空目录。无登录模式不支持监听非回环地址，也不应通过反向代理暴露到其他设备或公网。

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
|  **本机安全** | 回环监听 + 熔断器 + 审计日志 + 限流；不含账户体系 |
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
| **健康** | `/api/health`, `/api/stats`, `/api/metrics` | 系统状态 |
| **事件** | `/api/events`, `/api/events/{id}`, `/api/events/feedback` | 安全事件、人工反馈标签与复盘数据 |
| **MITRE** | `/api/mitre/search`, `/api/mitre/technique/{id}`, `/api/mitre/kill-chain`, `/api/mitre/attack-flow` | ATT&CK 知识库 |
| **CVE** | `/api/cve/search`, `/api/cve/{id}`, `/api/cve/by-mitre/{tech_id}` | 漏洞库 |
| **合规** | `/api/compliance/search`, `/api/compliance/{name}` | 法规库 |
| **剧本** | `/api/remediation/search`, `/api/remediation/{scenario}` | 应急响应 |
| **Agent** | `/api/agents`, `/api/agents/runtime` | 智能体运行时 |
| **ML 状态** | `/api/ml/status`, `/api/ml/models`, `/api/ml/datasets` | 三个数据集适配器及模型的部署、算法、阈值与错误状态（只读） |
| **RAG 索引状态** | `/api/knowledge/index/status` | ChromaDB 集合与文档数量（只读） |
| **会话** | `GET/POST /api/conversations`, `PATCH/DELETE /api/conversations/{id}` | 搜索、创建、重命名、置顶和删除本机研判会话 |
| **会话消息** | `GET /api/conversations/{id}/messages` | 恢复本机历史问答正文 |
| **人工处置** | `POST /api/dispatch` | 确认、升级、忽略事件；封禁/解封必须显式传入 `confirmed: true` |
| **联邦** | `/api/federation/status`, `/api/federation/events`, `/api/federation/blacklist` | 跨区域同步 |
| **WebSocket** | `/ws/chat` | 实时对话 |

### 人工处置安全边界

事件确认、升级和忽略只会变更本地事件状态。封禁或解封 IP 是高风险网络动作：控制台必须先显示二次确认对话框，API 也会拒绝任何未带 `confirmed: true` 的请求；即使已经确认，防火墙白名单、熔断器、审计日志和 `FIREWALL_BACKEND` 开关仍会继续生效。默认 `FIREWALL_BACKEND=disabled`，不会执行真实网络变更。

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
│   ├── security/         # 脱敏/熔断器/审计/限流
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
| v4.0.0 | 2026-09-03 | 移除登录、JWT、RBAC 与用户管理；控制台强制仅本机访问 |
| v3.1.0 | 2026-08-23 | HttpOnly Web 会话/CSRF、bcrypt 迁移、AI 金标准评测、数据完整性与 CI 安全门禁 |
| v3.0.0 | 2026-08-22 | 统一 CLI/onboarding/dashboard、自定义 UI、多厂商 Provider、系统安全凭据与企业默认边界 |
| v2.1.0 | 2026-07-23 | ML 训练评估流水线 / 前后端路由联调 / 前端测试 |
| v2.0.0 | 2026-07-08 | 多 Agent + TrueReAct + Docker Compose |
| v1.1 | 2026-06-15 | 单 Agent + 基础 API + 前端初版 |

---

## 许可证

本项目采用 [MIT License](LICENSE)。
