import os
import yaml
import asyncio
from pathlib import Path

# 统一环境初始化 (加载 .env + 设置项目根目录)
from backend.utils.env import init_environment
from backend.runtime_assets import config_path
init_environment()

# 数据模型（单数据源，Schema 定义以 models.py 为准）
from backend.storage.models import SCHEMA_SQL

from backend.llm.provider import LLMFactory
from backend.tools.registry import ToolRegistry
from backend.tools.threat_intel import ThreatIntelTool
from backend.tools.firewall import FirewallTool
from backend.tools.log_analyzer import LogAnalyzerTool
from backend.tools.alert_filter import AlertFilterTool
from backend.tools.cve_search import CVESearchTool
from backend.tools.geoip import GeoIPTool
from backend.agents.analyst import AnalystAgent
from backend.agents.intel import IntelAgent
from backend.agents.responder import ResponderAgent
from backend.agents.knowledge.knowledge_agent import KnowledgeAgent
from backend.agents.alert_filter.alert_filter_agent import AlertFilterAgent
from backend.agents.knowledge.agentic_rag import AgenticRAGEngine
from backend.orchestrator.core import Orchestrator
from backend.knowledge.mitre_attack import MitreAttackKnowledge
from backend.knowledge.compliance import ComplianceKnowledge
from backend.knowledge.cve_db import CVEDatabase
from backend.knowledge.threat_intel_kb import ActorKnowledge, MalwareKnowledge

# 统一日志
import logging
logger = logging.getLogger("secagentx")


def load_config(path: str = None) -> dict:
    if path is None:
        path = config_path()
    path = Path(path)
    if not path.exists():
        logger.info(f"[config] config file not found: {path}")
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _run_alembic_migrations():
    """启动时自动执行 Alembic 迁移（PostgreSQL 模式）。"""
    try:
        from alembic.config import Config
        from alembic import command
        migrations_dir = os.path.join(os.path.dirname(__file__), "storage", "migrations")
        alembic_cfg = Config(os.path.join(migrations_dir, "alembic.ini"))
        alembic_cfg.set_main_option("script_location", migrations_dir)
        command.upgrade(alembic_cfg, "head")
        logger.info("[init] Alembic 迁移完成: head")
    except Exception as e:
        logger.warning(f"[init] Alembic 迁移执行失败: {e}")
        logger.warning("[init] 请确认已安装 alembic (pip install alembic) 且数据库连接正常")


def init_db(db_path: str = None, force_sqlite: bool = False):
    """
    初始化数据库 Schema

    - PostgreSQL 模式: 自动执行 Alembic 迁移到最新版本
    - SQLite 模式: 直接执行 CREATE TABLE DDL

    参数:
        db_path: SQLite 数据库文件路径（仅在 SQLite 模式下使用）
        force_sqlite: 强制使用 SQLite 初始化（测试用）
    """
    from backend.storage.database import _is_postgres

    # PostgreSQL 模式：自动运行 Alembic 迁移
    if _is_postgres() and not force_sqlite:
        try:
            import alembic
            _run_alembic_migrations()
        except ImportError:
            logger.warning("[init] alembic 未安装 (pip install alembic)，跳过 Schema 自动化管理")
        except Exception as e:
            logger.error(f"[init] Alembic 迁移失败: {e}")
        return

    # SQLite 模式：使用 models.py 中的单数据源 DDL
    import sqlite3
    if db_path is None:
        db_path = os.getenv("SECAGENTX_DB_PATH", "data/secagentx.db")
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    _migrate_sqlite_schema(conn)
    conn.commit()
    conn.close()
    logger.info(f"[init] SQLite 数据库初始化: {db_path}")


def _migrate_sqlite_schema(conn):
    """SQLite 增量迁移：为已存在的旧表补齐缺失列（幂等，可重复执行）。

    历史库（早期版本创建）可能缺少后续版本新增的列，
    这里检测并 ALTER TABLE 补齐，避免 'no such column' 运行时错误。
    """
    import sqlite3

    def _ensure_column(table: str, column: str, ddl: str) -> bool:
        try:
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        except sqlite3.Error:
            return False
        if column not in cols:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
                logger.info(f"[migrate] 表 {table} 新增列 {column}")
                return True
            except sqlite3.Error as e:
                logger.warning(f"[migrate] 表 {table} 添加列 {column} 失败: {e}")
        return False

    # events 表历史版本缺少处置字段
    _ensure_column("events", "resolution", "TEXT DEFAULT ''")
    _ensure_column("events", "resolved_by", "TEXT DEFAULT ''")
    owner_added = _ensure_column(
        "conversations", "owner_id", "TEXT NOT NULL DEFAULT ''"
    )
    if owner_added:
        legacy_owner = os.getenv("SECAGENTX_LEGACY_CONVERSATION_OWNER", "admin")
        conn.execute(
            "UPDATE conversations SET owner_id = ? WHERE owner_id = ''",
            (legacy_owner,),
        )
    _ensure_column("conversations", "pinned", "INTEGER NOT NULL DEFAULT 0")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_conversations_owner "
        "ON conversations(owner_id)"
    )


def _check_api_keys():
    """启动时检查核心模型与可选威胁情报配置。"""
    runtime_provider = os.getenv("SECAGENTX_ACTIVE_PROVIDER", "")
    legacy_model = bool(os.getenv("DEEPSEEK_API_KEY") or os.getenv("QWEN_API_KEY"))
    model_ready = bool(runtime_provider or legacy_model)
    intel = {
        "VirusTotal": bool(os.getenv("VT_API_KEY")),
        "AbuseIPDB": bool(os.getenv("ABUSEIPDB_API_KEY")),
        "AlienVault OTX": bool(os.getenv("OTX_API_KEY")),
    }

    logger.info("\n" + "=" * 50)
    logger.info("  SecAgentX API Key 检查")
    logger.info("=" * 50)
    if model_ready:
        logger.info("  [OK] 活动模型 Provider 已配置")
    else:
        logger.warning("  [MISSING] 模型 Provider 未配置，请运行 secagentx onboard")
    enabled_intel = [name for name, ready in intel.items() if ready]
    if enabled_intel:
        logger.info("  [OK] 外部威胁情报: %s", ", ".join(enabled_intel))
    else:
        logger.info("  [OPTIONAL] 外部威胁情报未配置；使用本地知识与离线情报适配器")
    logger.info("=" * 50 + "\n")


def init_application(config: dict = None) -> Orchestrator:
    _check_api_keys()

    if config is None:
        config = load_config()

    from backend.storage.database import _is_postgres, get_sqlite_path
    if _is_postgres():
        init_db()
        logger.info("[init] database: PostgreSQL")
    else:
        db_path = get_sqlite_path()
        init_db(db_path)
        logger.info(f"[init] database: {db_path}")

    mitre = MitreAttackKnowledge()
    mitre_count = mitre.count()
    logger.info(f"[init] MITRE ATT&CK: {mitre_count['techniques']} techniques, {mitre_count['sub_techniques']} sub-techniques, {mitre_count['tactics']} tactics")
    compliance = ComplianceKnowledge()
    logger.info(f"[init] Compliance knowledge: {compliance.count()} regulations/standards")
    cve_db = CVEDatabase()
    logger.info(f"[init] CVE database: {cve_db.count()} vulnerabilities")
    actor_kb = ActorKnowledge()
    actor_count = actor_kb.count()
    logger.info(f"[init] Threat actors: {actor_count['actors']} ({', '.join(f'{k}:{v}' for k,v in actor_count.get('countries',{}).items())})")
    malware_kb = MalwareKnowledge()
    logger.info(f"[init] Malware: {malware_kb.count()} samples")

    tools = ToolRegistry()
    tools.register(ThreatIntelTool())
    # 读取 config 白名单，注入 FirewallTool（支持适配器模式）
    block_cfg = config.get("auto_operation", {}).get("block_protection", {})
    whitelist = block_cfg.get("whitelist_ips", None)
    fw_backend = os.getenv("FIREWALL_BACKEND", "disabled")
    fw_tool = FirewallTool(whitelist=whitelist, backend=fw_backend)
    fw_tool.agent_id = "orch-firewall"  # 审计日志标识
    tools.register(fw_tool)
    logger.info(f"[init] 防火墙后端: {fw_backend}")
    tools.register(LogAnalyzerTool())
    tools.register(AlertFilterTool())
    tools.register(CVESearchTool())
    tools.register(GeoIPTool())
    # ML 为可选能力：只有部署了真实训练模型时才注册，避免把未验证模型暴露给 Agent。
    try:
        from backend.tools.ml_detector import MLThreatDetectorTool
        ml_tool = MLThreatDetectorTool()
        if os.path.isfile(ml_tool._model_path):
            tools.register(ml_tool)
            logger.info("[init] ML 威胁检测模型已发现，将在首次调用时加载")
        else:
            logger.info("[init] ML 威胁检测未启用：未部署真实训练模型")
    except ImportError as e:
        logger.warning(f"[init] ML 威胁检测模块加载失败: {e}")
    except Exception as e:
        logger.warning(f"[init] ML 威胁检测初始化失败: {e}")
    logger.info(f"[init] tools: {tools.count()}")

    llm_configs = config.get("llm", {})
    deepseek_cfg = dict(llm_configs.get("deepseek", {}))
    qwen_cfg = dict(llm_configs.get("qwen", {}))
    # LLM fallback 配置（主 LLM 超时/失败时自动切换备用 LLM）
    _orchestrator_fb = dict(llm_configs.get("fallback", {})) if isinstance(llm_configs.get("fallback"), dict) else None

    for cfg in [deepseek_cfg, qwen_cfg]:
        key = cfg.get("api_key", "")
        if key.startswith("${") and key.endswith("}"):
            cfg["api_key"] = os.getenv(key[2:-1], "")

    # ═══ 修复：fallback 段的嵌套 config 也要做 env 插值 ═══
    # 否则 config.yaml fallback.config.api_key 的 "${QWEN_API_KEY}" 会以字面量传给 LLM，
    # 导致 fallback 请求 401/403。
    if _orchestrator_fb and isinstance(_orchestrator_fb, dict):
        _fb_cfg = _orchestrator_fb.get("config")
        if isinstance(_fb_cfg, dict):
            _fb_key = _fb_cfg.get("api_key", "")
            if isinstance(_fb_key, str) and _fb_key.startswith("${") and _fb_key.endswith("}"):
                _fb_cfg["api_key"] = os.getenv(_fb_key[2:-1], "")

    # 根据 LLM_PROVIDER 环境变量选择 LLM 提供商
    llm_provider = os.getenv(
        "SECAGENTX_ACTIVE_PROVIDER", os.getenv("LLM_PROVIDER", "deepseek")
    ).lower()
    orchestrator_llm_cfg = deepseek_cfg.copy()
    if _orchestrator_fb:
        orchestrator_llm_cfg["fallback"] = _orchestrator_fb
    logger.info(f"[init] LLM 提供商: {llm_provider}")

    # Agent 也使用同一 fallback 配置（主 LLM 超时/失败时自动切换备用 LLM）
    analyst = AnalystAgent(tools, llm_fallback_config=_orchestrator_fb)
    intel = IntelAgent(tools, llm_fallback_config=_orchestrator_fb)
    responder = ResponderAgent(tools, llm_fallback_config=_orchestrator_fb)
    knowledge = KnowledgeAgent(tools, llm_fallback_config=_orchestrator_fb)
    alert_filter = AlertFilterAgent(tools, llm_fallback_config=_orchestrator_fb)
    # v2.5: 报告生成员（Summary Agent）— 汇总所有专业 Agent 结果生成模板化最终报告
    from backend.agents.summary_agent import SummaryAgent
    summary = SummaryAgent(tools, llm_fallback_config=_orchestrator_fb)
    # v2.5: 事件分类器（Classifier Agent）— 判断安全事件模板分类
    from backend.agents.classifier_agent import ClassifierAgent
    classifier = ClassifierAgent(tools, llm_fallback_config=_orchestrator_fb)

    try:
        from backend.storage.chroma_store import VectorStore
        vector_store = VectorStore()
        # Qwen RAG 也传入 fallback 配置
        qwen = LLMFactory.get_qwen(qwen_cfg, fallback_config=_orchestrator_fb)
        max_rounds = config.get("agents", {}).get("knowledge", {}).get("max_retrieval_rounds", 3)
        rag_engine = AgenticRAGEngine(llm=qwen, vector_store=vector_store, max_rounds=max_rounds)
        # BGE 模型改为懒加载：首次查询时自动加载（模型已缓存，无需启动时预载）
        knowledge.set_rag_engine(rag_engine)
        logger.info(f"[init] RAG engine: enabled (max {max_rounds} rounds)")
    except Exception as e:
        rag_engine = AgenticRAGEngine(max_rounds=1)
        knowledge.set_rag_engine(rag_engine)
        logger.warning(f"[WARN] [init] RAG engine: FALLBACK MODE - ChromaDB 初始化失败")
        logger.info(f"      原因: {e}")
        logger.info(f"      影响: 知识检索将降级为关键词搜索，语义相关性下降")
        logger.info(f"      修复: 检查 chromadb 安装和 data/chromadb/ 目录权限")

    orchestrator = Orchestrator({
        **config.get("orchestrator", {}),
        "llm": orchestrator_llm_cfg,
    }, tools=tools)
    orchestrator.register_agent("analyst-001", "安全分析师", analyst,
                                "告警分析、日志分析、攻击溯源")
    orchestrator.register_agent("intel-001", "威胁情报员", intel,
                                "IOC查询、威胁情报关联")
    orchestrator.register_agent("responder-001", "应急响应员", responder,
                                "封禁IP、策略管理")
    orchestrator.register_agent("knowledge-001", "知识智能体", knowledge,
                                "MITRE ATT&CK、CVE查询")
    orchestrator.register_agent("alert-filter-001", "告警误报剔除专家", alert_filter,
                                "告警误报过滤：规则引擎+AI双层研判，将误报率从90%降至10%以下")
    orchestrator.register_agent("summary-001", "报告生成员", summary,
                                "汇总所有专业Agent分析结果，生成模板化最终综合报告")
    orchestrator.register_agent("classifier-001", "事件分类器", classifier,
                                "判断安全事件模板分类（漏洞分析/攻击检测/安全配置/威胁情报/应急响应）")

    stats = orchestrator.get_stats()
    logger.info(f"[init] SecAgentX ready: {stats['agents_count']} agents, {tools.count()} tools")

    # ═══════════════════════ 初始化跨区域联邦模块 ═══════════════════════
    orchestrator._federation = None
    try:
        from backend.federation import Federation
        federation = Federation(config.get("federation", {}))
        if federation.enabled:
            logger.info(f"[init] 跨区域联邦: 已启用 (region={federation.region_id}, peers={len(federation._peers)})")
        else:
            logger.info("[init] 跨区域联邦: 未启用")
        orchestrator._federation = federation
    except Exception as e:
        logger.warning(f"[init] 跨区域联邦: 加载失败 ({e})")

    # ═══════════════════════ 初始化零人工干预模块 ═══════════════════════
    _auto_modules = {}
    _background_tasks: list[asyncio.Task] = []
    auto_op_config = config.get("auto_operation", {})
    auto_enabled = auto_op_config.get("enabled", False)

    if auto_enabled:
        logger.info("\n[auto] 零人工干预模式已启用")

        # 1. 自动升级通知引擎
        try:
            from backend.escalation import AutoEscalation
            escalator = AutoEscalation(auto_op_config)
            _auto_modules["escalator"] = escalator
            esc_status = escalator.get_status()
            active_channels = [s["type"] for s in esc_status if s["enabled"]]
            logger.info(f"[auto] 升级通知引擎: {', '.join(active_channels) if active_channels else '仅控制台'}")

            # 将熔断器的自动恢复失败通知接入升级通知引擎
            try:
                from backend.security.circuit_breaker import circuit_breaker
                async def _cb_escalate(msg: str):
                    await escalator.escalate(
                        incident_id="circuit-breaker-auto-recovery",
                        summary=msg,
                        confidence=0.0,
                        reason="熔断器自动恢复失败，需人工介入",
                    )
                circuit_breaker.set_escalate_callback(_cb_escalate)
                logger.info("[auto] 熔断器自动恢复通知: 已接入升级引擎")
            except Exception as e:
                logger.warning(f"[auto] 熔断器通知接入失败: {e}")
        except Exception as e:
            escalator = None
            logger.info(f"[auto] 升级通知引擎: 加载失败 ({e})")

        # 2. 自动告警接入器
        ingestor = None
        try:
            from backend.auto_ingestor import AutoIngestor
            ingestor = AutoIngestor(orchestrator, escalator, auto_op_config)
            _auto_modules["ingestor"] = ingestor
            logger.info(f"[auto] 告警接入器: 已就绪 (在 api_server 启动时激活)")
        except Exception as e:
            logger.info(f"[auto] 告警接入器: 加载失败 ({e})")

        # 2.5 邮件安全接入器（可选，依赖 IMAP 配置）
        try:
            from backend.email_ingestor import EmailIngestor
            if ingestor is not None:
                email_ingestor = EmailIngestor(ingestor, auto_op_config)
                _auto_modules["email_ingestor"] = email_ingestor
                if email_ingestor._configured:
                    logger.info(f"[auto] 邮件接入器: 已就绪 ({email_ingestor.username}@{email_ingestor.imap_server})")
                else:
                    logger.info("[auto] 邮件接入器: 未配置 (设置 EMAIL_IMAP_SERVER/USERNAME/PASSWORD 后启用)")
            else:
                logger.info("[auto] 邮件接入器: 跳过 (告警接入器未就绪)")
        except Exception as e:
            logger.info(f"[auto] 邮件接入器: 加载失败 ({e})")

        # 3. 自动安全巡检器
        try:
            from backend.auto_patrol import AutoPatrol
            patrol = AutoPatrol(orchestrator, escalator, auto_op_config)
            _auto_modules["patrol"] = patrol
            logger.info(f"[auto] 安全巡检器: 已就绪 (间隔 {auto_op_config.get('patrol', {}).get('interval_seconds', 1800)}s)")
        except Exception as e:
            logger.info(f"[auto] 安全巡检器: 加载失败 ({e})")

        # 4. 防火墙工具注入置信度阈值
        try:
            block_threshold = auto_op_config.get("thresholds", {}).get("auto_block", 0.70)
            fw_tool = tools.get("firewall_manage")
            if fw_tool and hasattr(fw_tool, "_block_threshold"):
                fw_tool._block_threshold = block_threshold
                logger.info(f"[auto] 防火墙门控阈值: {block_threshold:.0%}")
        except Exception as e:
            logger.info(f"[auto] 防火墙门控: 配置失败 ({e})")

        logger.info("[auto] 初始化完成\n")
    else:
        logger.info("\n[auto] 零人工干预模式已禁用 (config.yaml: auto_operation.enabled=false)\n")

    # 将自动模块和后台任务挂载到 orchestrator 上，供 api_server 访问
    orchestrator._auto_modules = _auto_modules
    orchestrator._background_tasks = _background_tasks
    orchestrator._config = config

    stats = orchestrator.get_stats()
    logger.info(f"[init] SecAgentX ready: {stats['agents_count']} agents, {tools.count()} tools")
    return orchestrator


async def quick_query(orchestrator: Orchestrator, text: str) -> str:
    """快速查询 — 使用统一 TrueReAct 入口"""
    results = []
    async for chunk in orchestrator.process(text):
        if chunk["type"] in ("orchestrator_complete", "true_react_complete"):
            results.append(chunk.get("summary", chunk.get("content", "")))
    return "\n".join(results)
