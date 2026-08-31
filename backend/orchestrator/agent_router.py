"""
AgentRouter — 多智能体路由的二次校验层

职责:
  1. 接收 LLM 的 `route_to_agent` 调用
  2. 校验任务类型是否匹配 Agent 的声明能力
  3. 不匹配时重新路由到正确的 Agent，而不是直接拒绝
  4. 完全匹配时放行

核心逻辑:
  - 每个 Agent 注册时带有关键词列表（capability_keywords）
  - 路由校验提取任务文本中的关键词 → 匹配最合适的 Agent
  - 匹配度低于阈值时拒绝 + 给出建议
"""

from typing import Optional

# Agent 能力关键词映射表
AGENT_CAPABILITIES: dict[str, list[str]] = {
    "analyst-001": [
        "告警分析", "日志分析", "攻击溯源", "攻击链", "安全事件",
        "告警", "日志", "入侵", "异常", "检测", "分析", "溯源",
        "防火墙日志", "安全日志",
        "alert", "log", "intrusion", "anomaly", "detect",
    ],
    "intel-001": [
        "威胁情报", "IOC", "IP查询", "情报", "威胁指标",
        "威胁", "ip地址", "域名", "恶意", "情报关联", "信誉",
        "threat intel", "indicator", "malicious", "reputation",
    ],
    "responder-001": [
        "封禁", "解封", "拦截", "防火墙", "策略", "阻断", "处置",
        "block", "unblock", "firewall", "drop", "ban", "mitigate",
    ],
    "knowledge-001": [
        "MITRE", "ATT&CK", "CVE", "漏洞", "合规", "知识库",
        "战术", "技术", "杀伤链", "标准", "查询",
        "technique", "tactic", "vulnerability", "compliance",
    ],
    "alert-filter-001": [
        "误报", "误判", "过滤", "批量", "告警过滤",
        "噪声", "去重", "false positive", "filter", "noise",
    ],
}


def validate_route(agent_id: str, task: str) -> tuple[bool, str, Optional[str]]:
    """
    二次校验: LLM 的 Agent 路由决策是否合理。

    参数:
        agent_id: LLM 选择的 Agent ID
        task: LLM 分配的任务描述

    返回:
        (is_valid: bool, reason: str, suggested_agent: Optional[str])
    """
    if not task:
        return False, "任务描述为空", None

    task_lower = task.lower()
    capabilities = AGENT_CAPABILITIES.get(agent_id, [])

    if not capabilities:
        return True, "无能力定义，放行", None

    # 计算匹配度 — 至少命中一个关键词即放行
    # 注：不使用"匹配数/总关键词数"的比率，因为不同 Agent 关键词数量差异大，
    # 用比率会导致关键词多的 Agent 更难达到阈值
    matched = sum(1 for kw in capabilities if kw.lower() in task_lower)

    if matched >= 1:
        return True, f"命中 {matched} 个关键词，放行", None

    # 匹配度低 → 找更合适的 Agent
    best_agent = _find_best_agent(task_lower, exclude=agent_id)
    if best_agent:
        return (
            False,
            f"任务 '{task[:30]}...' 与 {agent_id} 的能力不匹配（仅命中 {matched} 个关键词），"
            f"建议路由到 {best_agent}",
            best_agent,
        )

    return True, "无更合适候选，放行", None


def _find_best_agent(task_lower: str, exclude: str = "") -> Optional[str]:
    """
    找到与任务最匹配的 Agent

    匹配策略:
      1. 优先匹配 keyword 在 task 中出现的次数（得分）
      2. 平局时优先选择 keyword 更长的一方（长关键词匹配更精确，
         如"封禁"比"恶意"更能准确描述封禁操作）
    """
    best_score = 0
    best_keyword_len = 0
    best_agent = None

    for agent_id, keywords in AGENT_CAPABILITIES.items():
        if agent_id == exclude:
            continue
        score = 0
        matched_keyword_len = 0
        for kw in keywords:
            kw_lower = kw.lower()
            if kw_lower in task_lower:
                score += 1
                matched_keyword_len = max(matched_keyword_len, len(kw))

        if score > best_score or (score == best_score and matched_keyword_len > best_keyword_len):
            best_score = score
            best_keyword_len = matched_keyword_len
            best_agent = agent_id

    if best_score > 0:
        return best_agent
    return None


def register_capabilities(agent_id: str, capabilities: list[str]):
    """
    动态注册/更新 Agent 的能力关键词（供插件化 Agent 注册使用）。

    参数:
        agent_id: Agent 唯一 ID（如 "analyst-001"）
        capabilities: 能力关键词列表

    使用方式:
        from backend.orchestrator.agent_router import register_capabilities
        register_capabilities("my-agent", ["关键能力1", "关键能力2", ...])
    """
    if not agent_id or not capabilities:
        return
    # 合并（保留已有的，追加新的）
    existing = AGENT_CAPABILITIES.get(agent_id, [])
    for kw in capabilities:
        if kw not in existing:
            existing.append(kw)
    AGENT_CAPABILITIES[agent_id] = existing
    import logging
    logging.getLogger("secagentx.router").info(
        f"Agent {agent_id} 能力注册: {len(existing)} 个关键词"
    )
