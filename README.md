# SecAgentX 4.0

> 一个可在本地运行的开源安全智能体，支持安全知识问答、事件研判、Agentic-RAG 知识检索和受控自动响应。

SecAgentX 面向安全研究、开发测试和本地安全分析场景。它通过多个职责明确的内部 Agent 协同处理任务，结合 Agentic-RAG、本地安全知识库、威胁情报查询和风险融合能力，对安全问题、日志、告警、IP、漏洞及网络事件进行分析，并生成带有证据依据的判断和处置建议。

SecAgentX 提供 Web 和 CLI 两种交互方式。普通安全知识问题直接返回简洁答案；安全事件则根据风险等级、分析证据和处置需求生成结构化研判结果。自动封禁及其他外部响应操作默认关闭，只有经过用户明确配置后才会启用。

## 核心能力

- **安全知识问答**：解释漏洞、攻击技术、安全配置和防御措施。
- **安全事件研判**：分析告警、日志、IP、域名、文件哈希和网络行为。
- **多 Agent 协作**：按照任务类型协调分析、情报、知识、响应等内部 Agent。
- **Agentic-RAG**：自主选择检索策略，从本地知识库查找并组织相关证据。
- **本地安全知识库**：内置 MITRE ATT&CK、CVE、CISA KEV、合规要求和响应剧本。
- **风险评分与证据融合**：综合多个分析信号形成风险判断和处置建议。
- **受控自动响应**：支持封禁、解除封禁和告警升级，默认关闭。
- **多模型接入**：支持 OpenAI、Anthropic 兼容接口以及常见云端和本地模型。
- **可选 ML 检测**：可训练并部署网络流量威胁检测模型，不影响核心功能运行。

## Agent 分工

| Agent | 主要职责 |
|---|---|
| 分析 Agent | 识别攻击行为、提取安全特征并判断事件性质 |
| 情报 Agent | 查询 IP、域名、漏洞和攻击组织相关情报 |
| 知识 Agent | 从本地安全知识库检索相关证据 |
| 告警过滤 Agent | 过滤重复、低价值或误报概率较高的告警 |
| 响应 Agent | 生成处置建议，并执行经过明确授权的响应动作 |
| 汇总 Agent | 汇总各 Agent 结论并生成最终回答 |

各 Agent 由统一任务路由协调，职责相互独立；涉及封禁等状态变更的动作仍受审批、白名单、熔断和审计机制约束。

## 快速开始

需要 Python 3.10 或更高版本。仓库已经包含预构建的 Web 界面，普通用户不需要安装 Node.js。

当前推荐直接从 GitHub 安装：

```powershell
python -m pip install --user pipx
python -m pipx ensurepath
pipx install "git+https://github.com/songruifeng1010/secagent.git"

secagentx onboard
secagentx dashboard
```

重新打开终端后运行 `secagentx onboard`，选择模型服务并完成连接验证。随后运行 `secagentx dashboard`，访问 `http://127.0.0.1:8000` 使用 Web 对话界面。

也可以克隆源码并安装：

```powershell
git clone https://github.com/songruifeng1010/secagent.git
cd secagent
python -m venv .venv
.venv\Scripts\python.exe -m pip install .
.venv\Scripts\secagentx.exe onboard
.venv\Scripts\secagentx.exe dashboard
```

Linux 和 macOS 将 `.venv\Scripts\python.exe`、`.venv\Scripts\secagentx.exe` 分别替换为 `.venv/bin/python`、`.venv/bin/secagentx`。

网络无法连接 GitHub 22 端口时，已配置 GitHub SSH Key 的用户可以通过 SSH 443 克隆：

```bash
git clone ssh://git@ssh.github.com:443/songruifeng1010/secagent.git
```

网络受限环境还可以下载 Release wheel，或使用项目提供的 `scripts/install_offline.ps1`、`scripts/install_offline.sh` 和完整 `wheelhouse/` 离线安装。

## 使用方式

```powershell
# 终端多轮对话
secagentx chat

# 直接提出安全问题
secagentx ask "什么是 SQL 注入？"

# 分析安全事件
secagentx ask "分析来自 45.33.32.156 的多次 SSH 登录失败"

# 启动 Web 对话界面
secagentx dashboard
```

`secagentx chat` 支持 `/new`、`/history`、`/resume`、`/model` 和 `/export` 等会话命令。普通知识问答直接显示 Markdown 正文，事件研判使用结构化报告；自动化脚本可通过 `secagentx ask "问题" --json` 获取机器可读结果。

API Key 默认保存到 Windows 用户级 DPAPI 加密凭据库；安装可选 `keyring` 后也可以使用系统 Keyring。凭据不会写入项目或明文 JSON，只有通过真实连接验证的 Provider 才会成为活动配置。

内置模型预设包括 DeepSeek、通义千问、OpenAI、Anthropic、Azure OpenAI、Gemini、OpenRouter、xAI、Kimi、Ollama 和 LM Studio。其他服务可以使用自定义 OpenAI 或 Anthropic 兼容接口。

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

## 能力与集成明细

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
