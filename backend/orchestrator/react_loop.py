"""
True ReAct 循环引擎（v2.1 — 真正的多智能体协同版）

核心改进:
  不再让单一 LLM 独自完成所有工具调用，而是引入 Agent 调度层:
    1. Orchestrator LLM 分析任务 → 判断需要哪个专业 Agent
    2. 路由到对应 Agent（analyst / intel / knowledge / alert-filter / responder）
    3. Agent 执行其专业分析（含工具调用）
    4. 结果聚合回 Orchestrator → 最终结论

  流程:
    Think (Orchestrator LLM) → 判断任务类型
      → Act: 路由到专业 Agent
        → Agent 内部 Think-Tool-Observe 循环
      → Observe: 聚合 Agent 分析结果
    → 最终综合研判
"""
import re
import uuid
import time
import json
import asyncio
import difflib
import logging
from typing import Optional, AsyncGenerator

logger = logging.getLogger("secagentx.orchestrator")

from ..tools.calling import (
    build_tools_for_llm, parse_tool_calls, ToolCallHistory,
)
from ..tools.execution_engine import UnifiedToolCallEngine
from .risk_scorer import RiskScorer
from ..models.output import (
    AgentResult, EvidencePackage, Finding, FinalResult, FinalVerdict,
    FinalSummary, build_final_result, parse_final_summary, final_to_markdown,
    predict_answer_mode,
)
from ..decision_fusion import FusionEngineFactory

# 从用户输入中提取目标 IP（供风险评分卡的 IP真实性 / 历史信誉维度使用）
_IP_EXTRACT_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


# Agent 路由提示词 — 让 LLM 识别需要哪个专业 Agent
AGENT_DISPATCH_PROMPT = """
## 多智能体协同工作流
你不是一个人在战斗，你身后有一个专业安全团队。根据任务类型，路由到对应的专业 Agent：

### 可用专业 Agent
{agent_descriptions}

### 路由规则
- **告警分析/日志分析/攻击溯源** → `analyst-001`（安全分析师）
- **威胁情报/IP查询/IOC验证** → `intel-001`（威胁情报员）
- **MITRE ATT&CK/CVE/合规查询** → `knowledge-001`（知识智能体）
- **告警误报判断/批量判定** → `alert-filter-001`（告警误报剔除专家）
- **封禁IP/解封/策略管理** → `responder-001`（应急响应员）
- **综合性或多步骤任务** → 你自己先用工具分析，再视情况路由到 Agent

### 路由方式
当你判断需要路由到某个 Agent 时，调用 router 工具:
```
route_to_agent(agent_id="analyst-001", task="分析这个告警的完整攻击链", context={...})
```

### 工作流示例
```
用户: "这个IP 45.33.32.156 是不是恶意的？"
→ 你: 路由到 intel-001 查威胁情报
→ intel-001: 返回 IP 多源情报交叉验证结果
→ 你: 收到报告 → 路由到 analyst-001 做攻击链分析
→ analyst-001: 返回分析报告
→ 你: 综合所有信息，给出最终结论
```
"""

TRUE_REACT_SYSTEM_PROMPT = """你是一个安全运营指挥官（SOC Manager），负责统筹多专业安全 Agent 协同工作。
重要：回复中不要使用 emoji/表情符号，一律用文字描述。

## 工作流程
你会进行多轮**思考→路由→观察**循环，直到问题解决：

- **思考 (THINK)**: 分析当前已知信息，判断需要哪个专业 Agent 或工具
- **路由 (ROUTE)**:
  - 需要专业知识 → `route_to_agent(agent_id="xxx", task="...")` 路由给专业 Agent
  - 需要查询数据 → 直接调用工具（threat_intel, cve_search, geoip 等）
- **观察 (OBSERVE)**: 查看 Agent 或工具返回的结果，评估下一步
- 当信息足够时，输出最终综合结论

## 思考精简规则（简化输出，严格遵守）
1. **每轮思考只写 2~3 句话（≤80 字）**：只说明"本轮决策 + 理由"，例如"信息不足，先查 CVE 再路由知识智能体"。
2. **不展开分析过程**：不要复述工具/Agent 已返回的内容，不要写"我发现了X，这说明Y，因此Z"这类长篇推理。
3. **不要输出最终结论草稿**：最终结论由报告阶段统一生成，思考阶段不要预先长篇总结。
4. **一次尽量并行路由/调用**：能一起做的工具调用和 Agent 路由放同一轮，减少来回轮数。

## 并行执行（强烈要求）
- **同一轮可同时发起多个 `route_to_agent` 和多个工具调用**（一并放入 tool_calls 数组）。
- 目标：**尽量在 2 轮以内完成全部路由**。标准场景（如加固建议/威胁分析）第 1 轮即可并行路由所有需要的 Agent，第 2 轮收尾即可。
- 不要一轮只路由一个 Agent 然后再"思考要不要路由下一个"，那样会浪费轮次、拖长输出。

## 核心原则
1. **专业的事交给专业的人**: 分析告警找 analyst-001，查情报找 intel-001，封禁找 responder-001
2. **并行优先**: 能同时路由的 Agent 一起路由
3. **避免重复**: 同一个问题不要重复调用同一个 Agent 或工具
4. **只读不写**: 除非用户明确要求执行操作
5. **注意私有IP**: 10.x.x.x、172.16-31.x.x、192.168.x.x 是私有/内网地址

## 标准协作链路（v2.5，按需路由，不必全部强制）
为保证报告完整性与质量，请尽量按以下顺序组织路由（视任务需要选择，不需要的环节可跳过）：
1. **analyst-001（安全分析师）**: 分析事件/告警/攻击行为
2. **knowledge-001（知识智能体）**: 关联 MITRE ATT&CK / CVE / 最佳实践
3. **responder-001（应急响应员）**: 评估处置方案 / 是否需要封禁
4. **summary-001（报告生成员）**: 汇总以上所有 Agent 结果，生成模板化最终报告

> 注意：summary-001 会自动在流程结束时被系统调用生成最终报告，你无需手动路由到它，
> 但若你想让报告更贴合用户诉求，可以在路由阶段结束后说明需要强调的重点。

## 证据纪律（严格遵守）
1. **假设与事实分离**: 没有证据支撑的判断（以"可能/推测/或许/不排除"开头）必须标注为「假设(Hypothesis)」，**不得参与置信度评分**。只有已获取的事实（工具返回、日志原文、Agent 结构化裁决）才能作为评分依据。
2. **缺失≠干净**: 威胁情报源因缺少 API Key 未查询，或查询失败时，该维度视为「未知(Unknown)」，**绝不能当作"无恶意证据"**。情报覆盖不足时应降低而非提高置信度。
3. **Agent 降级要注明**: 某个 Agent 曾调用失败后重试成功的，最终报告必须标注该 Agent「已降级(重试)」，并对其结果的权重心中有数。
4. **置信度可复现**: 最终报告的置信度必须引用确定性聚合结果（若已提供），不得自行编造新数值。报告需包含每个 Agent 的权重与置信度明细。

## 可用工具
{tools_desc}

请开始指挥你的安全团队。
"""


class TrueReActLoop:
    """
    多智能体协同 TrueReAct 循环（v2.1）

    核心改进:
    1. Orchestrator LLM 判断任务类型 → 路由到专业 Agent
    2. Agent 内部执行 Think-Tool-Observe 子循环
    3. 结果聚合回 Orchestrator 做最终综合研判

    使用方式:
        loop = TrueReActLoop(orchestrator)
        async for chunk in loop.run(user_text):
            # 处理流式事件
    """

    MAX_ROUNDS = 8
    ROUND_TIMEOUT = 45  # 每轮 LLM 思考最大等待秒数，超时直接终止循环

    # ─── 确定性置信度聚合（修复：最终置信度必须可复现、可解释） ───
    # 各 Agent 的固定权重，替代 LLM 在最终报告里"感觉"出来的数字。
    # 权重可调，但一经设定即对同一输入产生确定性结果。
    CONFIDENCE_WEIGHTS = {
        "analyst-001": 0.35,        # 安全分析师：告警/日志核心研判
        "intel-001": 0.25,          # 威胁情报员：多源交叉验证
        "responder-001": 0.20,      # 应急响应员：处置可行性
        "alert-filter-001": 0.10,   # 告警过滤：误报研判
        "knowledge-001": 0.10,      # 知识智能体：ATT&CK/CVE 关联
    }
    COVERAGE_PENALTY = 0.9          # 情报覆盖 33%~100% 时惩罚系数
    COVERAGE_PENALTY_LOW = 0.8     # 情报覆盖 <33% 时更强惩罚（情报基本不可信）
    MIN_CONF_NO_AGENT = 0.3         # 无任何 Agent 结构化裁决时置信度上限

    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.engine = UnifiedToolCallEngine(orchestrator.tools)
        self.round_count = 0
        self._trace_counter = 0

    def _trace_step(self, phase: str, round_number: int, actor: str,
                    input_: str = "", output: str = "", success=None,
                    duration_ms: int = 0, extra: Optional[dict] = None) -> dict:
        """构造可持久化、可经 WebSocket 传输的结构化执行轨迹。"""
        self._trace_counter += 1
        step = {
            "step_id": f"step-{self._trace_counter}",
            "phase": phase,
            "round": round_number,
            "actor": actor,
            "input": input_,
            "output": output,
            "success": success,
            "duration_ms": int(duration_ms or 0),
            "timestamp": time.time(),
        }
        if extra:
            step.update(extra)
        return step

    async def _emit_trace_steps(self, steps: list[dict]) -> AsyncGenerator[dict, None]:
        """把内部轨迹转换为稳定的 trace_step 事件。"""
        for step in steps or []:
            event = dict(step)
            event["type"] = "trace_step"
            yield event

    async def _persist_trajectory(self, conversation_id: str, steps: list[dict],
                                  total_duration_ms: int) -> None:
        """旁路保存轨迹；存储故障不得影响主分析链路。"""
        if not steps:
            return
        db = None
        try:
            from backend.storage.database import Repository
            from backend.storage.repositories.trajectory_repo import TrajectoryRepository
            db = Repository()
            owner_id = str(getattr(self.orchestrator, "owner_id", "system") or "system")
            repo = TrajectoryRepository(db, owner_id=owner_id)
            await repo.save_trajectory(
                conversation_id=conversation_id,
                trajectory=steps,
                total_duration_ms=int(total_duration_ms or 0),
            )
        except Exception as exc:
            logger.debug("轨迹持久化失败（旁路）: %s", exc)
        finally:
            close = getattr(db, "close", None) if db is not None else None
            if close:
                try:
                    result = close()
                    if hasattr(result, "__await__"):
                        await result
                except Exception:
                    pass

    # ═══════════ 确定性置信度聚合 ═══════════
    def _aggregate_confidence(self, agent_results: list) -> dict:
        """
        用固定权重加权聚合各 Agent 的结构化置信度。

        agent_results: 每项为
          {
            "agent_id": str,
            "confidence": float|None,  # Agent 结构化裁决的置信度
            "verdict": str|None,
            "degraded": bool,          # 该 Agent 曾失败后重试成功
            "failed": bool,            # 该 Agent 最终失败
            "coverage": float|None,    # intel 工具情报覆盖度
          }

        规则:
          - 未返回结构化置信度的 Agent 不参与加权（避免 0 分拉低）
          - 降级（曾失败重试成功）的 Agent 权重减半
          - 情报覆盖不足时整体置信度打折（缺失源不能"装干净"）
          - 无任何 Agent 有效裁决 → 强制低置信度 + 需人工
        """
        total_weight = 0.0
        weighted_sum = 0.0
        details = []
        degraded_count = 0

        for r in agent_results:
            agent_id = r.get("agent_id", "")
            weight = self.CONFIDENCE_WEIGHTS.get(agent_id, 0.0)
            conf = r.get("confidence")
            if conf is None:
                # 无结构化裁决的 Agent 不参与聚合（但记录，用于审计）
                details.append({
                    "agent_id": agent_id,
                    "weight": weight,
                    "confidence": None,
                    "verdict": r.get("verdict"),
                    "degraded": bool(r.get("degraded")),
                    "failed": bool(r.get("failed")),
                })
                continue
            conf = float(conf)
            if r.get("degraded"):
                weight *= 0.5
                degraded_count += 1
            weighted_sum += conf * weight
            total_weight += weight
            details.append({
                "agent_id": agent_id,
                "weight": round(weight, 4),
                "confidence": conf,
                "verdict": r.get("verdict"),
                "degraded": bool(r.get("degraded")),
                "failed": bool(r.get("failed")),
            })

        if total_weight <= 0:
            return {
                "confidence": self.MIN_CONF_NO_AGENT,
                "verdict": "unknown",
                "needs_human": True,
                "details": details,
                "coverage": None,
                "degraded_count": degraded_count,
                "reason": "无任何 Agent 返回结构化裁决，需人工介入",
            }

        confidence = weighted_sum / total_weight

        # 情报覆盖惩罚：取所有 Agent 中 intel 工具覆盖度的最小值
        coverages = [r.get("coverage") for r in agent_results if r.get("coverage") is not None]
        min_coverage = min(coverages) if coverages else None
        if min_coverage is not None:
            if min_coverage >= 1.0:
                pass  # 全覆盖：无惩罚
            elif min_coverage > 0.33:
                confidence *= self.COVERAGE_PENALTY
            else:
                confidence *= self.COVERAGE_PENALTY_LOW

        # 无任何 Agent 失败但全部失败的情况
        any_success = any(
            r.get("confidence") is not None and not r.get("failed")
            for r in agent_results
        )
        if not any_success:
            confidence = min(confidence, self.MIN_CONF_NO_AGENT)

        if confidence >= 0.7:
            verdict = "malicious"
        elif confidence >= 0.4:
            verdict = "suspicious"
        else:
            verdict = "unknown"

        return {
            "confidence": round(confidence, 4),
            "verdict": verdict,
            "needs_human": confidence < 0.4,
            "details": details,
            "coverage": min_coverage,
            "degraded_count": degraded_count,
            "reason": None,
        }

    # ═══════════ 最终结构化结果组装（JSON-first） ═══════════
    @staticmethod
    def _pick_recommended_action(agent_results: list) -> str:
        """从各 Agent 裁决中推断建议动作（确定性，不依赖 LLM）。"""
        best = "monitoring"
        best_conf = -1.0
        for r in agent_results or []:
            conf = r.get("confidence")
            verdict = r.get("verdict")
            if conf is None or verdict is None:
                continue
            if conf > best_conf:
                best_conf = conf
                if verdict == "malicious" and conf >= 0.7:
                    best = "block"
                elif verdict == "suspicious":
                    best = "escalate"
                else:
                    best = "monitoring"
        return best

    # ═══════════ Decision Fusion 接入（Sense-Decide 分离，v2.4） ═══════════
    def _run_fusion(self, agent_results: list, target_ip: Optional[str]) -> tuple:
        """
        运行决策融合（可替换引擎），构造 EvidencePackage 并融合。

        Returns:
            (fusion_result: dict|None, evidence_packages: list, risk_scorecard: dict|None)
            - fusion_result: None 表示 fusion 未启用/异常（上层回退旧聚合）
            - risk_scorecard: 已用 fusion 重算（仅消费 fusion 结果）
        """
        if not agent_results:
            return None, [], None

        # 构造标准化证据包
        evidence_packages = []
        for r in agent_results:
            try:
                ep = EvidencePackage.model_validate({
                    "agent_id": r.get("agent_id", ""),
                    "agent_name": r.get("agent_name", ""),
                    "status": "failed" if r.get("failed") else
                              "degraded" if r.get("degraded") else "success",
                    "findings": r.get("findings", []),
                    "evidence_confidence": r.get("evidence_confidence") or
                                           r.get("confidence") or 0.5,
                    "leaning": r.get("leaning") or r.get("verdict") or "unknown",
                    "leaning_confidence": r.get("leaning_confidence") or
                                          r.get("confidence") or 0.5,
                    "coverage": r.get("coverage"),
                    "missing_sources": r.get("missing_sources", []),
                    "iocs": r.get("iocs", {}),
                    "technique_ids": r.get("technique_ids", []),
                    "degraded": bool(r.get("degraded")),
                    "failed": bool(r.get("failed")),
                })
                evidence_packages.append(ep)
            except Exception as e:
                logger.debug("证据包构造失败: %s", e)
                continue

        # 读取融合引擎配置（可替换模块）
        fusion_cfg = self.orchestrator.get_config().get("decision_fusion", {}) \
            if self.orchestrator.get_config() else {}
        engine_name = fusion_cfg.get("engine", "dempster_shafer")
        enabled = fusion_cfg.get("enabled", True)

        if not enabled:
            return None, evidence_packages, None

        try:
            engine = FusionEngineFactory.get_engine(engine_name, fusion_cfg)
            fusion = engine.fuse(evidence_packages)
            fusion_result = fusion.model_dump(mode="json")
            # 风险评分卡：只消费 fusion 结果（不再读单个 Agent verdict）
            risk_scorecard = self._score_risk({
                "fusion_result": fusion_result,
                "evidence_packages": [ep.model_dump(mode="json") for ep in evidence_packages],
                "agent_results": agent_results,  # 兼容兜底
                "ip": target_ip,
                "event_history": self._load_event_history(target_ip),
            })
            # 融合结果同步风险分（score 决策：取 risk_score）
            fusion_result["risk_score"] = risk_scorecard.get("risk_score", 0)
            return fusion_result, evidence_packages, risk_scorecard
        except Exception as e:
            logger.warning("决策融合失败，回退旧聚合: %s", e)
            return None, evidence_packages, None

    async def _run_knowledge_branch(
        self, text: str, conversation_id: str, intent: dict,
        history_messages: list = None,
    ) -> AsyncGenerator[dict, None]:
        """安全知识分支：优先 Agentic-RAG，无接地结果时按配置降级直答。"""
        start = time.time()
        yield {
            "type": "true_react_start",
            "conversation_id": conversation_id,
            "max_rounds": 1,
            "content": (
                "  **知识问答模式**\n\n"
                f"**用户输入**: {text[:200]}\n"
                f"**意图识别**: 安全知识（非安全事件，不进行威胁评分）\n"
            ),
        }

        config = self.orchestrator.get_config()
        if not isinstance(config, dict):
            config = {}
        knowledge_cfg = (config.get("agents") or {}).get("knowledge") or {}
        free_qa_fallback_enabled = knowledge_cfg.get("free_qa_fallback", True)

        content = ""
        sources = []
        grounding_score = 0.0
        grounding_detail = ""
        has_grounding = False
        retrieval_rounds = 0
        rag_used = False
        free_qa_fallback = False

        info = self.orchestrator.agents.get("knowledge-001")
        rag_engine = getattr(getattr(info, "instance", None), "rag_engine", None)
        if rag_engine is not None and hasattr(rag_engine, "answer"):
            progress_events = []

            async def progress_cb(event):
                if isinstance(event, dict):
                    progress_events.append(event)

            try:
                import inspect
                params = inspect.signature(rag_engine.answer).parameters
                if "progress_cb" in params:
                    result = await rag_engine.answer(text, progress_cb=progress_cb)
                else:
                    result = await rag_engine.answer(text)
                    progress_events.append({
                        "phase": "complete", "message": "知识库检索完成", "entities": [],
                    })
                result = result if isinstance(result, dict) else {}
                rag_used = True
                content = str(result.get("answer") or "")
                sources = result.get("structured_sources") or result.get("sources") or []
                grounding_score = float(result.get("grounding_score") or 0.0)
                grounding_detail = str(result.get("grounding_detail") or "")
                has_grounding = bool(result.get("has_grounding"))
                retrieval_rounds = int(result.get("retrieval_rounds") or 0)
                for event in progress_events:
                    yield {
                        "type": "rag_progress",
                        "conversation_id": conversation_id,
                        **event,
                    }
            except Exception as exc:
                logger.warning("知识库检索失败，降级为 LLM 直答: %s", exc)
                rag_used = False
                content = ""

        needs_llm_fallback = not rag_used or (not has_grounding and free_qa_fallback_enabled)
        if rag_used and not has_grounding and free_qa_fallback_enabled:
            free_qa_fallback = True

        if rag_used:
            yield {
                "type": "rag_sources",
                "conversation_id": conversation_id,
                "sources": sources,
                "grounding_score": grounding_score,
                "grounding_detail": grounding_detail,
                "has_grounding": has_grounding,
                "free_qa_fallback": free_qa_fallback,
            }

        if needs_llm_fallback:
            content = ""
            try:
                messages = [{
                    "role": "system",
                    "content": (
                        "你是 SecAgentX 的安全知识助手。请准确、简洁地回答问题；"
                        "事实不确定时明确说明，不得编造漏洞编号、攻击证据或情报结论。"
                    ),
                }]
                messages.extend((history_messages or [])[-4:])
                messages.append({"role": "user", "content": text})
                stream = self.orchestrator.llm.chat_stream(messages)
                if hasattr(stream, "__await__"):
                    stream = await stream
                async for chunk in stream:
                    content += chunk
                    yield {
                        "type": "stream", "content": chunk,
                        "agent_id": "orch-001", "free_qa": free_qa_fallback,
                    }
            except Exception as exc:
                logger.warning("知识问答降级失败: %s", exc)
                content = "抱歉，当前知识检索和问答服务暂时不可用，请稍后重试。"

        knowledge_result = {
            "status": "completed",
            "conversation_id": conversation_id,
            "rounds": 1,
            "needs_human": False,
            "score": None,
            "is_knowledge": True,
            "summary_text": content or "（无内容）",
            "verdict": {},
            "summary_report": {
                "template_type": "安全知识",
                "risk_summary": content or "",
                "core_findings": [],
                "recommended_actions": [],
                "detail": content or "",
                "table": [],
            },
            "agent_results": [],
            "decision_path": [],
            "rag": {
                "used": rag_used,
                "sources": sources,
                "grounding_score": grounding_score,
                "grounding_detail": grounding_detail,
                "has_grounding": has_grounding,
                "retrieval_rounds": retrieval_rounds,
                "free_qa_fallback": free_qa_fallback,
            },
        }

        elapsed = (time.time() - start) * 1000
        yield {
            "type": "true_react_complete",
            "rounds": 1,
            "total_tool_calls": 0,
            "total_agent_calls": 0,
            "content": content or "（无内容）",
            "summary": content or "（无内容）",
            "total_duration_ms": elapsed,
            "tool_call_history": [],
            "structured_result": knowledge_result,
            "answer_mode": "rag",
            "score": None,
        }

    async def _run_free_qa_branch(
        self, text: str, conversation_id: str, intent: dict,
        history_messages: list = None,
    ) -> AsyncGenerator[dict, None]:
        """普通问答分支：不访问安全知识库，也不生成威胁评分卡。"""
        start = time.time()
        content = ""
        yield {
            "type": "true_react_start",
            "conversation_id": conversation_id,
            "max_rounds": 1,
            "content": "  **自由问答模式**\n",
            "answer_mode": "free",
        }
        try:
            messages = [{
                "role": "system",
                "content": (
                    "你是 SecAgentX 助手。请直接、准确、简洁地回答一般问题。"
                    "不要把普通咨询解释成安全事件，也不要生成风险评分。"
                ),
            }]
            messages.extend((history_messages or [])[-4:])
            messages.append({"role": "user", "content": text})
            stream = self.orchestrator.llm.chat_stream(messages)
            if hasattr(stream, "__await__"):
                stream = await stream
            async for chunk in stream:
                content += chunk
                yield {
                    "type": "stream", "content": chunk,
                    "agent_id": "orch-001", "free_qa": True,
                }
        except Exception as exc:
            logger.warning("自由问答失败: %s", exc)
            content = "抱歉，当前问答服务暂时不可用，请稍后重试。"
        elapsed = (time.time() - start) * 1000
        yield {
            "type": "true_react_complete",
            "rounds": 1,
            "total_tool_calls": 0,
            "total_agent_calls": 0,
            "content": content or "（无内容）",
            "summary": content or "（无内容）",
            "total_duration_ms": elapsed,
            "tool_call_history": [],
            "structured_result": None,
            "answer_mode": "free",
            "score": None,
        }

    async def _invoke_classifier(self, text: str) -> dict:
        """
        调用 classifier-001（事件分类器 / 意图识别器）判断意图。

        返回 dict: {template_type, category_reason, priority, risk_baseline, is_knowledge_query}
        失败/未注册时用关键词预判兜底 —— 永不阻断主链路。
        """
        try:
            from ..models.output import classify_template
            kw_type = classify_template(text)
        except Exception:
            kw_type = "安全知识"

        base = {
            "template_type": kw_type,
            "category_reason": "关键词预判",
            "priority": "中",
            "is_knowledge_query": (kw_type == "安全知识"),
            "answer_mode": predict_answer_mode(kw_type, text),
        }

        info = self.orchestrator.agents.get("classifier-001")
        if not info or not info.enabled:
            return base
        try:
            from ..models.message import AgentMessage, MessageType
            msg = AgentMessage(
                sender="orchestrator",
                receiver="classifier-001",
                msg_type=MessageType.TASK_ASSIGN,
                payload={"task": text, "params": {}},
                context={},
            )
            result: dict = {}
            async for chunk in info.instance.process_message(msg):
                if chunk.get("type") == "agent_result":
                    result = chunk.get("structured_result") or chunk.get("structured", {})
            if result and result.get("template_type"):
                # 规范化：确保字段齐全
                result.setdefault("category_reason", "LLM 判断")
                result.setdefault("priority", "中")
                result["is_knowledge_query"] = bool(
                    result.get("is_knowledge_query")
                    or result["template_type"] == "安全知识"
                )
                result.setdefault(
                    "answer_mode",
                    predict_answer_mode(result["template_type"], text),
                )
                logger.info("[classifier] 意图识别: %s（%s）is_knowledge=%s",
                            result["template_type"], result.get("category_reason", ""),
                            result["is_knowledge_query"])
                return result
        except Exception as e:
            logger.debug("ClassifierAgent 调用失败，用关键词预判: %s", e)
        return base

    async def _invoke_summary_agent(
        self, task: str, agent_results: list,
        fusion_verdict: Optional[dict], risk_scorecard: Optional[dict],
        template_type: str = "",
    ) -> dict:
        """
        调用 summary-001（报告生成员）生成模板化最终报告。

        失败/未注册时返回 {}，由调用方回退旧逻辑 —— 主链路永不阻断。
        """
        info = self.orchestrator.agents.get("summary-001")
        if not info or not info.enabled:
            return {}
        try:
            from ..models.message import AgentMessage, MessageType
            msg = AgentMessage(
                sender="orchestrator",
                receiver="summary-001",
                msg_type=MessageType.TASK_ASSIGN,
                payload={
                    "task": task,
                    "agent_results": agent_results,
                    "fusion_verdict": fusion_verdict or {},
                    "risk_scorecard": risk_scorecard or {},
                    "template_type": template_type,
                },
                context={},
            )
            summary: dict = {}
            async for chunk in info.instance.process_message(msg):
                if chunk.get("type") == "agent_result":
                    summary = chunk.get("structured_result") or chunk.get("structured", {})
            return summary or {}
        except Exception as e:
            logger.warning("SummaryAgent 调用失败，回退旧逻辑: %s", e)
            return {}

    async def _build_final_result(
        self, *, status: str, conversation_id: str, rounds: int,
        total_tool_calls: int, total_agent_calls: int,
        messages: list, last_content: str,
        agg: Optional[dict], risk_scorecard: Optional[dict],
        agent_results: list, force_needs_human: bool = False,
        fusion_result: Optional[dict] = None,
        evidence_packages: Optional[list] = None,
        target_ip: Optional[str] = None,
        task: str = "",
        template_type: str = "",
    ) -> FinalResult:
        """
        组装编排器最终结构化结果（FinalResult JSON）。

        - 置信度 / 风险评分全部来自确定性计算（agg / risk_scorecard / fusion_result），
          LLM 不得改写
        - LLM 只负责生成解释性 summary_text（structured_output → FinalSummary）
        - structured_output 失败时降级用 last_content 作为 summary_text —— 主链路永不阻断
        """
        final_messages = list(messages)
        if agg and not agg.get("needs_human"):
            final_messages.append({
                "role": "system",
                "content": (
                    "【确定性置信度裁决 - 不可修改】基于各 Agent 结构化裁决加权聚合，"
                    f"综合置信度 = {agg.get('confidence', 0):.2f}（{agg.get('verdict', 'unknown')}）。\n"
                    f"权重明细: {json.dumps(agg.get('details', []), ensure_ascii=False)}\n"
                    "你只需在 json 的 summary_text 字段中做人类可读总结，"
                    "不得自行编造或修改置信度数值。"
                ),
            })

        summary_prompt = {
            "role": "user",
            "content": (
                "请基于以上全部信息，以 json 格式输出最终总结。"
                "JSON 字段: summary_text(总结), suggested_action(建议动作), "
                "needs_human_reason(如需人工介入的原因)。"
                "只填写解释性内容，不得修改任何给定的置信度/风险评分数值。"
                "语义一致性要求：当最终裁决为 unknown 或标记需人工介入时，"
                "summary_text 必须如实说明原因（证据不足/证据冲突/信息缺失），"
                "**不得声称高置信度或给出确定性结论**；"
                "单个 Agent 的置信度高不代表整体裁决置信度高，二者不得混为一谈。"
            ),
        }

        # ═══ v2.5: 优先调用 Summary Agent（报告生成员）生成模板化最终报告 ═══
        summary_report: dict = {}
        summary_text = ""
        suggested_action = ""
        if agent_results:
            # 组装融合裁决（供 Summary Agent 引用，不重新裁决）
            fv_for_summary = None
            if fusion_result:
                fv_for_summary = fusion_result.get("verdict", {})
            summary_report = await self._invoke_summary_agent(
                task, agent_results, fv_for_summary, risk_scorecard,
                template_type=template_type,
            )
            if summary_report:
                summary_text = (
                    summary_report.get("risk_summary")
                    or summary_report.get("summary_text")
                    or ""
                ).strip()
                suggested_action = (
                    summary_report.get("suggested_action") or ""
                ).strip()
            else:
                summary_text = ""
                suggested_action = ""

        # 回退：Summary Agent 未产出时用 LLM 直接生成总结
        if not summary_text:
            final_messages.append(summary_prompt)
            try:
                raw = await self.orchestrator.llm.structured_output(final_messages, FinalSummary)
                fs = parse_final_summary(raw)
                summary_text = (fs.summary_text or "").strip()
                suggested_action = (fs.suggested_action or "").strip()
            except Exception as e:
                logger.warning("最终总结 structured_output 失败，降级用最后结论文本: %s", e)

        if not summary_text:
            summary_text = (last_content or "").strip()[:2000]

        # ── 综合判定（优先 Fusion 结果，回退旧聚合） ──
        risk_probability = 0.0
        if fusion_result:
            # 唯一 final verdict 来自 Decision Fusion
            fv = fusion_result.get("verdict", {})
            verdict_val = fv.get("verdict", "unknown")
            confidence = fv.get("confidence", 0.0)
            risk_probability = fv.get("risk_probability", 0.0)   # v2.6: 与置信度分离
            risk_level = (risk_scorecard or {}).get("risk_level",
                                                    fv.get("risk_level", "低危"))
            decision_path = fusion_result.get("decision_path", [])
            if not suggested_action:
                suggested_action = fv.get("recommended_action", "monitoring")
            needs_human = (
                force_needs_human
                or bool(fv.get("needs_human", False))
                or bool((risk_scorecard or {}).get("needs_human", False))
            )
        else:
            # 回退：旧确定性聚合
            verdict_val = (agg or {}).get("verdict", "unknown")
            confidence = (agg or {}).get("confidence", 0.0)
            # 旧聚合没有独立 risk_probability → 用 confidence 近似（兼容）
            risk_probability = confidence
            risk_level = (risk_scorecard or {}).get("risk_level", "低危")
            decision_path = []
            if not suggested_action:
                suggested_action = self._pick_recommended_action(agent_results)
            needs_human = (
                force_needs_human
                or bool((agg or {}).get("needs_human", False))
                or bool((risk_scorecard or {}).get("needs_human", False))
            )

        # 各 Agent 结果规范化为 AgentResult
        agent_result_list = []
        for r in agent_results or []:
            try:
                agent_result_list.append(AgentResult.model_validate({
                    "agent_id": r.get("agent_id", ""),
                    "agent_name": r.get("agent_name", ""),
                    "confidence": r.get("confidence"),
                    "verdict": r.get("verdict"),
                    "findings": r.get("findings", []),
                    "evidence_confidence": r.get("evidence_confidence"),
                    "leaning": r.get("leaning") or r.get("verdict"),
                    "leaning_confidence": r.get("leaning_confidence") or r.get("confidence"),
                    "degraded": bool(r.get("degraded")),
                    "missing_sources": r.get("missing_sources", []),
                    "key_evidence": r.get("key_evidence", []),
                    "risk_level": r.get("risk_level"),
                }))
            except Exception:
                agent_result_list.append(AgentResult())

        # ── Evidence Chain 证据链（v2.6）──
        # 回答"为什么 / 依据是什么 / 调用了什么工具"：
        # 每个 Agent 一条 {agent, verdict, evidence(结论), basis(依据), tools([工具])}
        evidence_chain = []
        for r in agent_results or []:
            tools = r.get("tools") or []
            evidence = (r.get("risk_summary") or r.get("key_evidence") or [])
            if isinstance(evidence, list):
                evidence = "；".join(str(x) for x in evidence[:3])
            basis = (r.get("detail") or "")[:200]
            # 没有 Agent 单独内容时，跳过（避免空链）
            if not (evidence or basis):
                continue
            evidence_chain.append({
                "agent_id": r.get("agent_id", ""),
                "agent_name": r.get("agent_name", "") or r.get("agent_id", ""),
                "verdict": r.get("verdict", "unknown"),
                "confidence": r.get("confidence"),
                "evidence": str(evidence)[:300],
                "basis": str(basis),
                "tools": list(tools),
            })

        final_result = build_final_result(
            status=status,
            conversation_id=conversation_id,
            rounds=rounds,
            total_tool_calls=total_tool_calls,
            total_agent_calls=total_agent_calls,
            needs_human=needs_human,
            summary_text=summary_text,
            verdict=FinalVerdict(
                verdict=verdict_val,
                risk_probability=risk_probability,
                confidence=confidence,
                risk_level=risk_level,
                recommended_action=suggested_action,
            ),
            confidence_aggregate=agg or {},
            risk_scorecard=risk_scorecard or {},
            agent_results=agent_result_list,
            tool_call_history=self.engine.history.to_dict(),
            fusion_result=fusion_result or {},
            decision_path=decision_path,
            summary_report=summary_report,
            evidence_chain=evidence_chain,
        )
        return final_result

    def _render_aggregate_summary(self, agg: dict) -> str:
        """把确定性聚合结果渲染为最终报告附录（前端直接展示）"""
        lines = [
            "\n\n---",
            "### 确定性置信度裁决（可复现）",
            f"- **综合置信度**: **{agg['confidence']:.0%}**（{agg['verdict']}）",
            f"- **需人工介入**: {'是' if agg['needs_human'] else '否'}",
        ]
        for d in agg.get("details", []):
            c = f"{d['confidence']:.0%}" if d.get("confidence") is not None else "无结构化裁决"
            tag = ""
            if d.get("degraded"):
                tag = " 已降级"
            if d.get("failed"):
                tag = " ❌失败"
            lines.append(f"- {d['agent_id']}: 权重 {d['weight']:.0%} × 置信度 {c}{tag}")
        if agg.get("coverage") is not None:
            lines.append(f"- 情报覆盖度: {agg['coverage']:.0%}（缺失源按'未知'处理，不视为无恶意）")
        if agg.get("reason"):
            lines.append(f"- {agg['reason']}")
        return "\n".join(lines)

    # ═══════════ 可解释风险评分卡（v2.3） ═══════════
    @staticmethod
    def _load_event_history(ip: Optional[str]) -> Optional[list]:
        """惰性查询该 IP 的历史事件（SQLite EventRepository）。

        查询不可用（PostgreSQL 模式 / 无数据目录 / 表未初始化）时返回 None，
        由评分器按"历史信誉未启用"处理，绝不阻断主链路。
        """
        if not ip:
            return None
        try:
            from ..storage.database import Database
            from ..storage.repositories.event_repo import EventRepository
            db = Database()
            repo = EventRepository(db)
            return repo.get_events_by_ip(ip, limit=10)
        except Exception as e:
            logger.debug("历史信誉查询不可用（%s），评分卡将跳过该维度", e)
            return None

    @staticmethod
    def _load_asset_profile(ip: Optional[str]) -> Optional[dict]:
        """惰性查询该 IP 的资产画像（SQLite AssetRepository）。

        查询不可用（PostgreSQL 模式 / 表未初始化 / 无匹配资产）时返回 None，
        由评分器按"资产维度未知（中性）"处理，绝不阻断主链路。
        """
        if not ip:
            return None
        try:
            from ..storage.database import Database
            from ..storage.repositories.asset_repo import AssetRepository
            db = Database()
            repo = AssetRepository(db)
            return repo.get_by_ip(ip)
        except Exception as e:
            logger.debug("资产画像查询不可用（%s），资产维度按未知处理", e)
            return None

    def _score_risk(self, ctx: dict) -> dict:
        """风险评分统一入口（注入资产画像 + 上下文元数据）。

        仅注入已存在字段；查询失败/无数据时自动按"未知（中性）"处理，不阻断主链路。
        """
        ip = ctx.get("ip")
        ctx.setdefault("asset", self._load_asset_profile(ip))
        # 上下文元数据：IP 归属信息（geoip 结果可由外部预先注入）
        if "ip_info" not in ctx:
            ctx["ip_info"] = self._load_ip_info(ip)
        # 告警元数据：IP 关联的最近事件（取最近一条的严重度/MITRE）
        history = ctx.get("event_history")
        if history is None:
            history = self._load_event_history(ip)
            ctx["event_history"] = history
        alert_meta = {}
        if history:
            latest = history[0]
            alert_meta = {
                "severity": latest.get("severity"),
                "mitre_tactic": latest.get("mitre_tactic_id") or latest.get("mitre_tactic"),
            }
        ctx["alert_meta"] = alert_meta
        return RiskScorer.score(ctx)

    @staticmethod
    def _load_ip_info(ip: Optional[str]) -> Optional[dict]:
        """获取 IP 归属信息。

        设计决策：不在同步评分路径发起外部 HTTP（geoip 为 async 工具，由
        intel Agent 已查询后经 ctx['ip_info'] 注入）。此处仅对私有地址给出
        确定性归属结果；其余返回 None 表示不可用，上下文维度按中性处理。
        """
        if not ip:
            return None
        try:
            from ipaddress import ip_address
            addr = ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return {"org": "局域网", "isp": "内网", "note": "私有/保留地址", "source": "local"}
        except ValueError:
            pass
        return None

    @staticmethod
    def _render_risk_scorecard(scorecard: dict) -> str:
        """把风险评分卡渲染为最终报告附录（前端可直接展示 markdown）"""
        lines = [
            "\n\n---",
            "### 可解释风险评分（可复现）",
            f"- **最终风险评分**: **{scorecard['risk_score']}**（{scorecard['risk_level']}）",
            f"- **需人工介入**: {'是' if scorecard.get('needs_human') else '否'}",
        ]
        for d in scorecard.get("dimensions", []):
            sign = "+" if d["delta"] >= 0 else ""
            lines.append(f"- {d['name']}: {sign}{d['delta']}（{d['reason']}）")
        lines.append(f"- 汇总: {scorecard.get('summarized', '')}")
        return "\n".join(lines)

    def _build_agent_router_tool(self) -> dict:
        """构建 route_to_agent 工具定义（LLM function calling 用）"""
        agents = self.orchestrator.agents
        agent_enum = []
        agent_descriptions = []
        for aid, info in agents.items():
            agent_enum.append(aid)
            agent_descriptions.append(f"  - {aid}: {info.name} — {info.description}")

        return {
            "type": "function",
            "function": {
                "name": "route_to_agent",
                "description": "路由任务到专业安全 Agent。当需要专业知识时使用此工具，而不是自己硬分析。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "enum": agent_enum,
                            "description": "目标 Agent ID",
                        },
                        "task": {
                            "type": "string",
                            "description": "要交给 Agent 分析的具体任务描述",
                        },
                        "context": {
                            "type": "object",
                            "description": "附加上下文信息（如已查询到的IP信息、日志片段等）",
                            "default": {},
                        },
                    },
                    "required": ["agent_id", "task"],
                },
            },
        }

    async def _route_to_agent(self, agent_id: str, task: str, context: dict = None) -> dict:
        """
        路由任务到专业 Agent，并获取其分析结果（结构化 + 文本）

        这是"多智能体协同"的核心实现:
          1. 构造 AgentMessage 传给目标 Agent
          2. Agent 内部执行其专用的 process_message() 流程
          3. 返回结构化裁决结果 + 分析文本

        注意: 路由二次校验（AgentRouter）在调用方 run() 中执行，
        本函数只负责转发。
        """
        # 可观测性：记录 Agent 调用
        try:
            from backend.monitoring.metrics import record_agent_call
            record_agent_call(agent_id)
        except Exception:
            pass

        agent_info = self.orchestrator.agents.get(agent_id)
        if not agent_info or not agent_info.enabled:
            return {
                "error": f"Agent {agent_id} 不可用",
                "content": f"Agent {agent_id} 未找到或已禁用",
            }

        agent = agent_info.instance
        from ..models.message import AgentMessage, MessageType

        message = AgentMessage(
            sender="orchestrator",
            receiver=agent_id,
            msg_type=MessageType.TASK_ASSIGN,
            payload={
                "task": task,
                "params": context or {},
                "text": task,
            },
            context=context or {},
        )

        # Agent 内部执行分析（含工具调用）
        agent_result = {"content": "", "structured": {}}
        async for chunk in agent.process_message(message):
            if chunk.get("type") == "agent_result":
                agent_result["content"] = chunk.get("content", "")
                agent_result["structured"] = chunk.get("structured", {})
                agent_result["structured_result"] = chunk.get("structured_result") or chunk.get("structured", {})
                agent_result["tool_calls"] = chunk.get("tool_calls", [])
                agent_result["agent_trace"] = chunk.get("agent_trace", [])
                agent_result["duration_ms"] = chunk.get("duration_ms", 0)
            elif chunk.get("type") == "agent_error":
                agent_result["error"] = chunk.get("error", "")
            elif chunk.get("type") == "stream":
                pass  # 不转发 agent 内部流式内容到前端，避免混乱

        return agent_result

    async def _consume_llm_stream(self, messages: list, tools_def: list, rnd: int) -> tuple:
        """
        异步消费 LLM 流式响应，返回 (content, tool_calls_raw)

        将原来的流式消费逻辑提取为独立方法，以便上层做超时控制。
        """
        content = ""
        tool_calls_raw = []
        # 调用前做上下文压缩（防 token 超限）
        messages = self._compact_context(messages)
        async for stream_chunk in self.orchestrator.llm.chat_with_tools_stream(
            messages, tools_def, tool_choice="auto",
        ):
            if stream_chunk["type"] == "text":
                content += stream_chunk["content"]
            elif stream_chunk["type"] == "tool_calls":
                tool_calls_raw = stream_chunk.get("tool_calls", [])
        return content, tool_calls_raw

    # ═══════════ 上下文管理（商用化关键） ═══════════
    MAX_CONTEXT_MESSAGES = 40      # 最大消息条数（含历史）
    MAX_CONTEXT_CHARS = 200_000    # 最大字符数（粗粒度 token 估算）

    def _compact_context(self, messages: list) -> list:
        """压缩对话上下文，防止多轮累积导致 token 超限。

        策略：
          1. 保留首条 system（含角色定义）与末条 user 提问
          2. 中间按"字符总量"从最新往旧保留，超出上限则丢弃旧轮次
          3. 若工具结果过长，截断单条消息内容
        """
        if not messages:
            return messages
        # system 消息（首条）与当前提问（末条）必须保留
        head = [m for m in messages if m.get("role") == "system"]
        body = [m for m in messages if m.get("role") != "system"]
        if not body:
            return head or messages

        # 总字符估算，从旧到新累加，超出即从头部裁剪
        total = sum(len(str(m.get("content", ""))) for m in head)
        kept = []
        for m in reversed(body):  # 从最新往旧
            mlen = len(str(m.get("content", "")))
            if len(kept) >= self.MAX_CONTEXT_MESSAGES - len(head):
                break
            if total + mlen > self.MAX_CONTEXT_CHARS and kept:
                break
            total += mlen
            kept.append(m)
        kept.reverse()

        # 截断超长单条消息（通常是工具结果）
        truncated = []
        for m in kept:
            content = m.get("content", "")
            if isinstance(content, str) and len(content) > 30_000:
                m = dict(m)
                m["content"] = content[:30_000] + "\n...(截断)"
            truncated.append(m)

        return head + truncated

    async def run(self, text: str, history_messages: list = None) -> AsyncGenerator[dict, None]:
        """
        运行多智能体协同 ReAct 循环

        Orchestrator LLM 负责"指挥"（路由到哪个 Agent），
        专业 Agent 负责"干活"（执行具体分析）。
        """
        start = time.time()
        conversation_id = uuid.uuid4().hex[:12]

        # 输入守卫必须位于任何 LLM、Agent 或工具调度之前。
        guard_notice = ""
        try:
            guard = getattr(self.orchestrator, "adversarial_guard", None)
            if guard is not None:
                decision = guard.check(text, conversation_id)
                if not isinstance(decision, dict):
                    decision = {}
                if decision.get("blocked"):
                    yield {
                        "type": "adversarial_blocked",
                        "conversation_id": conversation_id,
                        "severity": decision.get("severity", "high"),
                        "findings": decision.get("findings", []),
                        "content": decision.get("message", "输入已被安全策略拦截"),
                    }
                    elapsed = (time.time() - start) * 1000
                    yield {
                        "type": "true_react_complete",
                        "rounds": 0,
                        "total_tool_calls": 0,
                        "total_agent_calls": 0,
                        "content": decision.get("message", "输入已被安全策略拦截"),
                        "summary": "输入被对抗防护策略拦截",
                        "total_duration_ms": elapsed,
                        "needs_human_intervention": True,
                        "structured_result": {
                            "status": "blocked",
                            "conversation_id": conversation_id,
                            "is_adversarial_blocked": True,
                            "adversarial": decision,
                        },
                        "agent_trace": [],
                        "score": None,
                    }
                    return
                if decision.get("action") == "warn":
                    from backend.security.adversarial.guard import INJECTION_GUARD
                    guard_notice = INJECTION_GUARD.format(
                        severity=decision.get("severity", "unknown")
                    )
        except Exception as exc:
            logger.debug("输入守卫不可用，按旁路策略继续: %s", exc)

        # ——— 构建工具列表（包含 route_to_agent 路由工具） ———
        # 指挥官只暴露只读工具；处置类（firewall_manage）须路由到 responder-001
        tools = self.orchestrator.get_readonly_tools().list_tools()
        tools_def = build_tools_for_llm(tools)
        # 注入路由工具
        router_def = self._build_agent_router_tool()
        tools_def.append(router_def)

        router_tool_name = router_def["function"]["name"]

        tools_desc_lines = []
        for t in tools:
            params_str = "; ".join(
                f"{k}({'必填' if k in t.parameters.get('required', []) else '可选'})"
                for k in t.parameters.get("parameters", {}).get("properties", {})
            )
            tools_desc_lines.append(f"- {t.name}: {t.description} | 参数: {params_str or '无'}")
        # 添加路由工具到描述
        agent_desc_lines = []
        for aid, info in self.orchestrator.agents.items():
            agent_desc_lines.append(f"  - {aid}: {info.name} — {info.description}")
        tools_desc_lines.append(f"- route_to_agent: 路由任务到专业Agent | 参数: agent_id(必填), task(必填)")
        tools_desc = "\n".join(tools_desc_lines)

        # ——— 注入 Agent 描述到系统提示词 ———
        agent_descriptions = "\n".join(
            f"  - `{aid}`: {info.name} — {info.description}"
            for aid, info in self.orchestrator.agents.items()
        )
        system_content = TRUE_REACT_SYSTEM_PROMPT.format(tools_desc=tools_desc) + \
            "\n\n### 你的安全团队\n" + agent_descriptions + \
            "\n\n路由到 Agent 后，Agent 会返回结构化分析结果（含裁决、置信度、证据）。" \
            "请基于所有 Agent 的返回结果，给出你的最终综合研判。\n"
        if guard_notice:
            system_content += "\n" + guard_notice

        messages = [{"role": "system", "content": system_content}]
        if history_messages:
            messages.extend(history_messages[-10:])
        messages.append({"role": "user", "content": text})

        yield {
            "type": "true_react_start",
            "conversation_id": conversation_id,
            "max_rounds": self.MAX_ROUNDS,
            "content": (
                "  **多智能体协同模式启动**\n\n"
                "工作流:  **指挥官思考 (Think)** → **路由到专业 Agent (Route)** → **观察结果 (Observe)** → **再思考...**\n"
                f"**用户输入**: {text[:200]}{'...' if len(text) > 200 else ''}\n"
                f"**可用 Agent**: {len(self.orchestrator.agents)} 个专业安全 Agent\n"
            ),
        }

        total_tool_calls = 0
        total_agent_calls = 0
        last_round_content = ""  # 用于检测重复输出
        trace_events = []        # 全程轨迹（工具 + Agent 调度），供 agent_trace 输出

        # ── 确定性置信度聚合的数据收集 ──
        collected_agent_results = []   # 每轮路由的 Agent 结构化裁决
        agent_failed_once = set()      # 曾失败过的 Agent（用于标记"降级重试"）

        # ── 可解释风险评分：从用户输入提取目标 IP ──
        target_ip = None
        _ip_matches = _IP_EXTRACT_RE.findall(text)
        if _ip_matches:
            target_ip = _ip_matches[0]

        # ── v2.6: 意图识别（Intent Classifier）→ 决定走"知识问答"还是"威胁分析" ──
        intent = await self._invoke_classifier(text)
        template_type = intent.get("template_type", "安全知识")
        is_knowledge_query = bool(intent.get("is_knowledge_query"))
        answer_mode = intent.get("answer_mode") or predict_answer_mode(template_type, text)

        # ═══ v2.8: 一般问答 / RAG 知识 / 威胁分析三态路由 ═══
        if is_knowledge_query and answer_mode == "free":
            config = self.orchestrator.get_config()
            if not isinstance(config, dict):
                config = {}
            knowledge_cfg = (config.get("agents") or {}).get("knowledge") or {}
            if knowledge_cfg.get("free_qa_direct", True):
                async for c in self._run_free_qa_branch(
                    text, conversation_id, intent, history_messages,
                ):
                    yield c
                return

        if is_knowledge_query and answer_mode in {"free", "rag"}:
            async for c in self._run_knowledge_branch(
                text, conversation_id, intent, history_messages,
            ):
                yield c
            return

        for rnd in range(1, self.MAX_ROUNDS + 1):
            self.round_count = rnd

            yield {
                "type": "true_react_think",
                "round": rnd,
                "content": f"\n\n---\n\n###  第 {rnd} 轮 — 指挥官思考决策\n",
            }

            # ═══════════════════ LLM 思考（含超时熔断）═══════════════════
            try:
                content = ""
                tool_calls_raw = []
                # 为 LLM 调用加上超时熔断，防止单轮卡死整个循环
                llm_task = asyncio.create_task(
                    self._consume_llm_stream(messages, tools_def, rnd)
                )
                done, pending = await asyncio.wait(
                    [llm_task],
                    timeout=self.ROUND_TIMEOUT,
                )
                if pending:
                    # 超时了！取消 LLM 任务，直接输出当前已收集的内容
                    llm_task.cancel()
                    try:
                        await llm_task
                    except asyncio.CancelledError:
                        pass
                    # 如果超时且没有任何反馈，输出超时熔断消息并终止循环
                    if not content and not tool_calls_raw:
                        yield {
                            "type": "true_react_timeout",
                            "round": rnd,
                            "content": (
                                f"\n---\n**第 {rnd} 轮 LLM 思考超时（>{self.ROUND_TIMEOUT}s），"
                                f"已自动熔断，终止分析循环**\n\n"
                                f"可能原因:\n"
                                f"- DeepSeek API 响应缓慢，请检查 API Key 是否有效、账户余额是否充足\n"
                                f"- 网络连接不稳定，可尝试切换到 Qwen 或其他 LLM 后端\n\n"
                                f"建议: 重试操作，或将问题拆分成更小的步骤分别提问\n"
                            ),
                        }
                        # 输出 final 后再 return
                        elapsed = (time.time() - start) * 1000
                        timeout_msg = (
                            f"分析超时熔断: LLM 在第 {rnd} 轮思考超过 "
                            f"{self.ROUND_TIMEOUT}s，已终止"
                        )
                        final_result = build_final_result(
                            status="timeout",
                            conversation_id=conversation_id,
                            rounds=rnd,
                            total_tool_calls=total_tool_calls,
                            total_agent_calls=total_agent_calls,
                            needs_human=True,
                            summary_text=timeout_msg,
                            verdict=FinalVerdict(
                                verdict="unknown", confidence=0.0,
                                risk_level="低危", recommended_action="escalate",
                            ),
                            confidence_aggregate={},
                            risk_scorecard={},
                            agent_results=[],
                            tool_call_history=self.engine.history.to_dict(),
                        )
                        yield {
                            "type": "true_react_complete",
                            "rounds": rnd,
                            "total_tool_calls": total_tool_calls,
                            "total_agent_calls": total_agent_calls,
                            "content": timeout_msg,
                            "summary": timeout_msg,
                            "total_duration_ms": elapsed,
                            "tool_call_history": self.engine.history.to_dict(),
                            "needs_human_intervention": True,
                            # 新增字段
                            "structured_result": final_result.model_dump(mode="json"),
                            "agent_trace": trace_events,
                            "score": final_result.score,
                        }
                        return
                else:
                    # 正常完成，取出结果
                    content, tool_calls_raw = llm_task.result()
            except Exception as e:
                err_msg = str(e) or "API 认证失败，请检查 DEEPSEEK_API_KEY 是否有效"
                logger.exception("TrueReAct 第 %d 轮 LLM 调用失败", rnd, exc_info=True)
                # 同时携带 error 字段，前端才能显示具体错误（此前仅 content 字段被前端忽略）
                yield {"type": "error", "content": f"LLM 调用失败: {err_msg}", "error": err_msg}
                return

            tool_calls = parse_tool_calls(
                {"choices": [{"message": {"tool_calls": tool_calls_raw}}]},
                source="true_react", round_number=rnd,
            )

            if tool_calls_raw:
                assistant_msg = {"role": "assistant", "content": content or ""}
                assistant_msg["tool_calls"] = tool_calls_raw
                messages.append(assistant_msg)
            elif content:
                messages.append({"role": "assistant", "content": content})

            if content:
                yield {"type": "true_react_think_content", "round": rnd, "content": content}

            # ═══════ 重复内容检测（防止 LLM 原地打转）═══════
            # 升级：整段相等 → 相似度 ≥90% 判重（如"重新路由给知识智能体"与
            # "重新尝试路由给知识智能体"这类近似重复也视为打转）
            _is_repeat = False
            if content and last_round_content and not tool_calls_raw:
                try:
                    _ratio = difflib.SequenceMatcher(
                        None, content, last_round_content
                    ).ratio()
                    _is_repeat = _ratio >= 0.9
                except Exception:
                    _is_repeat = (content == last_round_content)
            if _is_repeat:
                yield {
                    "type": "true_react_duplicate",
                    "round": rnd,
                    "content": (
                        f"\n---\n**检测到 LLM 连续两轮输出相同内容且未调用工具，"
                        f"判定为死循环，自动终止**\n\n"
                        f"可能原因: LLM API 返回缓存结果或模型推理异常\n"
                        f"建议: 等待几秒后重试\n"
                    ),
                }
                elapsed = (time.time() - start) * 1000
                duplicate_msg = (
                    "分析异常终止: 检测到 LLM 连续两轮输出相同内容且未调用工具，"
                    "判定为死循环"
                )
                final_result = build_final_result(
                    status="error",
                    conversation_id=conversation_id,
                    rounds=rnd,
                    total_tool_calls=total_tool_calls,
                    total_agent_calls=total_agent_calls,
                    needs_human=True,
                    summary_text=content or duplicate_msg,
                    verdict=FinalVerdict(
                        verdict="unknown", confidence=0.0,
                        risk_level="低危", recommended_action="escalate",
                    ),
                    confidence_aggregate={},
                    risk_scorecard={},
                    agent_results=[],
                    tool_call_history=self.engine.history.to_dict(),
                )
                yield {
                    "type": "true_react_complete",
                    "rounds": rnd,
                    "total_tool_calls": total_tool_calls,
                    "total_agent_calls": total_agent_calls,
                    "content": content or duplicate_msg,
                    "summary": content or duplicate_msg,
                    "total_duration_ms": elapsed,
                    "tool_call_history": self.engine.history.to_dict(),
                    "needs_human_intervention": True,
                    # 新增字段
                    "structured_result": final_result.model_dump(mode="json"),
                    "agent_trace": trace_events,
                    "score": final_result.score,
                }
                return
            if content:
                last_round_content = content

            # ═══════ 无工具调用 → 结束 ═══════
            if not tool_calls:
                # ── 确定性置信度聚合（兼容字段，fusion 未启用时兜底） ──
                agg = None
                if collected_agent_results:
                    agg = self._aggregate_confidence(collected_agent_results)

                # ── Decision Fusion（统一决策框架，v2.4） ──
                #   fusion_result 非 None → RiskScorer 已用 fusion 重算（只消费 fusion 结果）
                #   fusion_result 为 None → 回退旧 RiskScorer（读 agent_results）
                fusion_result = None
                evidence_packages = None
                risk_scorecard = None
                if collected_agent_results:
                    fusion_result, evidence_packages, risk_scorecard = \
                        self._run_fusion(collected_agent_results, target_ip)
                    if risk_scorecard is None:
                        # fusion 未启用/异常 → 旧逻辑兜底
                        risk_scorecard = self._score_risk({
                            "agent_results": collected_agent_results,
                            "ip": target_ip,
                            "event_history": self._load_event_history(target_ip),
                        })

                # ── 组装结构化最终结果（JSON-first） ──
                final_result = await self._build_final_result(
                    status="completed",
                    conversation_id=conversation_id,
                    rounds=rnd,
                    total_tool_calls=total_tool_calls,
                    total_agent_calls=total_agent_calls,
                    messages=messages,
                    last_content=content or "分析完成",
                    agg=agg,
                    risk_scorecard=risk_scorecard,
                    agent_results=collected_agent_results,
                    fusion_result=fusion_result,
                    evidence_packages=evidence_packages,
                    target_ip=target_ip,
                    task=text,
                    template_type=template_type,
                )
                content_text = final_to_markdown(final_result)

                elapsed = (time.time() - start) * 1000
                # 可观测性：记录对话轮数
                try:
                    from backend.monitoring.metrics import record_conversation_rounds
                    record_conversation_rounds(rnd)
                except Exception:
                    pass
                yield {
                    "type": "true_react_complete",
                    "rounds": rnd,
                    "total_tool_calls": total_tool_calls,
                    "total_agent_calls": total_agent_calls,
                    "content": content_text,
                    "summary": final_result.summary_text or content_text,
                    "total_duration_ms": elapsed,
                    "tool_call_history": self.engine.history.to_dict(),
                    "confidence_aggregate": agg,
                    "risk_scorecard": risk_scorecard,
                    # 新增字段（兼容迁移：旧字段全部保留）
                    "structured_result": final_result.model_dump(mode="json"),
                    "agent_trace": trace_events,
                    "score": final_result.score,
                }
                return

            # ═══════════════════ 路由 & 执行 ═══════════════════
            yield {
                "type": "true_react_act",
                "round": rnd,
                "tool_calls_count": len(tool_calls),
                "content": f"  **第{rnd}轮 — 决定执行 {len(tool_calls)} 个操作**\n\n",
            }

            # 分流：route_to_agent 调用 vs 普通工具调用
            agent_calls = [tc for tc in tool_calls if tc.tool_name == router_tool_name]
            tool_calls_only = [tc for tc in tool_calls if tc.tool_name != router_tool_name]

            # 执行普通工具（并行）
            if tool_calls_only:
                for tc in tool_calls_only:
                    total_tool_calls += 1
                    yield {
                        "type": "true_react_tool_call",
                        "round": rnd, "tool_name": tc.tool_name,
                        "arguments": tc.arguments,
                        "content": f"  [工具] **{tc.tool_name}**\n```json\n{json.dumps(tc.arguments, ensure_ascii=False, indent=2)}\n```\n",
                    }

                # 执行前二次校验：指挥官不允许直接调用处置类工具
                # （即便 LLM 输出越权调用，也被拦截并提示走 responder-001）
                allowed = self.orchestrator.READ_ONLY_TOOLS
                blocked = [tc for tc in tool_calls_only if tc.tool_name not in allowed]
                if blocked:
                    for tc in blocked:
                        total_tool_calls -= 1
                        logger.warning(
                            f"[rbac] 指挥官尝试调用越权工具 {tc.tool_name}，已拦截（须路由 responder-001）"
                        )
                        # 可观测性：记录被拦截的工具调用
                        try:
                            from backend.monitoring.metrics import record_tool_call
                            record_tool_call(tc.tool_name, success=False)
                        except Exception:
                            pass
                        yield {
                            "type": "true_react_tool_result",
                            "round": rnd, "tool_name": tc.tool_name,
                            "success": False, "duration_ms": 0,
                            "content": (
                                f"  [拦截] **{tc.tool_name}** — 指挥官无处置权限，"
                                f"请通过 route_to_agent 路由到 responder-001 执行\n"
                            ),
                        }
                        trace_events.append({
                            "type": "tool", "tool_name": tc.tool_name,
                            "round": rnd, "success": False, "blocked": True,
                        })
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc.call_id,
                            "content": json.dumps({
                                "error": f"工具 {tc.tool_name} 不在指挥官权限范围，"
                                          f"请路由到 responder-001 处置"
                            }, ensure_ascii=False),
                        })
                    tool_calls_only = [tc for tc in tool_calls_only if tc.tool_name in allowed]

                tool_results = await self.engine.execute(tool_calls_only)

                # 可观测性：记录工具调用
                try:
                    from backend.monitoring.metrics import record_tool_call
                    for r in tool_results:
                        record_tool_call(r.call.tool_name, success=r.success)
                except Exception:
                    pass

                yield {"type": "true_react_observe", "round": rnd, "content": f"  **第{rnd}轮 — 工具执行结果**\n\n"}
                for r in tool_results:
                    data_preview = json.dumps(r.result if r.success else {"error": r.error}, ensure_ascii=False, indent=2)
                    if len(data_preview) > 600:
                        data_preview = data_preview[:600] + "\n... (截断)"
                    yield {
                        "type": "true_react_tool_result",
                        "round": rnd, "tool_name": r.call.tool_name,
                        "success": r.success, "duration_ms": r.duration_ms,
                        "content": f"  {'[OK]' if r.success else '[FAIL]'} **{r.call.tool_name}** — {'成功' if r.success else '失败'} ({r.duration_ms:.0f}ms)\n```json\n{data_preview}\n```\n",
                    }
                    trace_events.append({
                        "type": "tool", "tool_name": r.call.tool_name,
                        "round": rnd, "success": r.success, "duration_ms": r.duration_ms,
                    })
                    messages.append(r.to_llm_message())

            # 执行 Agent 路由（串行，每个 Agent 独立分析）
            if agent_calls:
                yield {
                    "type": "true_react_agent_route",
                    "round": rnd,
                    "agent_calls_count": len(agent_calls),
                    "content": f"\n  **第{rnd}轮 — 路由到 {len(agent_calls)} 个专业 Agent**\n\n",
                }

                for ac in agent_calls:
                    agent_id = ac.arguments.get("agent_id", "")
                    task = ac.arguments.get("task", "")
                    context = ac.arguments.get("context", {})
                    total_agent_calls += 1

                    # 防御：LLM 可能返回空 agent_id / 空 task 的无效路由调用
                    if not agent_id or not task:
                        logger.warning(
                            f"[router] 跳过无效路由调用 (agent_id={agent_id!r}, task={task!r}, round={rnd})"
                        )
                        yield {
                            "type": "true_react_agent_error",
                            "round": rnd, "agent_id": agent_id or "unknown",
                            "content": (
                                f"  [Agent] 路由调用参数不完整（agent_id={agent_id!r}, "
                                f"task={task!r}），已跳过该轮无效路由\n"
                            ),
                        }
                        messages.append({
                            "role": "tool",
                            "tool_call_id": ac.call_id or f"route_invalid_{rnd}",
                            "content": json.dumps(
                                {"error": "无效路由调用: agent_id 与 task 不能为空"},
                                ensure_ascii=False,
                            ),
                        })
                        continue

                    yield {
                        "type": "true_react_agent_dispatch",
                        "round": rnd, "agent_id": agent_id, "task": task,
                        "content": f"  [Agent] **{agent_id}** 正在分析...\n  > 任务: {task}\n",
                    }

                    # 调用 Agent
                    # ── AgentRouter 二次校验 ──
                    from .agent_router import validate_route
                    is_valid, reason, suggested = validate_route(agent_id, task)
                    if not is_valid and suggested:
                        # LLM 路由错误，自动修正到正确的 Agent
                        logger.warning(
                            f"[router] 路由修正: {agent_id} → {suggested} "
                            f"(任务={task[:40]}, 原因={reason})"
                        )
                        yield {
                            "type": "true_react_route_correction",
                            "round": rnd,
                            "from": agent_id,
                            "to": suggested,
                            "reason": reason,
                            "content": f"  [路由修正] {agent_id} → {suggested}: {reason}\n",
                        }
                        agent_id = suggested
                    elif not is_valid:
                        logger.warning(
                            f"[router] 路由警告: {agent_id} 不匹配任务 '{task[:40]}' ({reason})"
                        )

                    agent_result = await self._route_to_agent(agent_id, task, context)

                    if "error" in agent_result:
                        agent_failed_once.add(agent_id)
                        yield {
                            "type": "true_react_agent_error",
                            "round": rnd, "agent_id": agent_id,
                            "content": f"  [Agent] **{agent_id}** 分析失败: {agent_result['error']}\n",
                        }
                        # 收集失败记录（供确定性聚合 + 风险评分）
                        collected_agent_results.append({
                            "agent_id": agent_id,
                            "confidence": None,
                            "verdict": None,
                            "degraded": False,
                            "failed": True,
                            "coverage": None,
                            "missing_sources": [],
                            "key_evidence": [],
                            "risk_level": None,
                        })
                        messages.append({
                            "role": "tool",
                            "tool_call_id": ac.call_id or f"route_{agent_id}",
                            "content": json.dumps({"error": agent_result["error"]}, ensure_ascii=False),
                        })
                    else:
                        # Agent 分析成功，注入结构化结果到 LLM 消息
                        agent_output_text = agent_result.get("content", "")
                        agent_structured = agent_result.get("structured_result") or agent_result.get("structured", {})

                        # 收集结构化裁决（供确定性聚合 + 风险评分）
                        # 若该 Agent 曾失败后重试成功 → 标记降级，聚合时权重减半
                        _degraded = agent_id in agent_failed_once
                        _coverage = None
                        _missing_sources = []
                        for _tc in agent_result.get("agent_trace") or agent_result.get("tool_calls") or []:
                            if _tc.get("tool") == "threat_intel":
                                _coverage = _tc.get("coverage")
                                _missing_sources = _tc.get("missing_sources", [])
                        collected_agent_results.append({
                            "agent_id": agent_id,
                            "agent_name": agent_structured.get("agent_name") or agent_id,
                            "confidence": agent_structured.get("confidence"),
                            "verdict": agent_structured.get("verdict"),
                            "degraded": _degraded,
                            "failed": False,
                            "coverage": _coverage,
                            "missing_sources": _missing_sources,
                            "key_evidence": agent_structured.get("key_evidence", []),
                            "risk_level": agent_structured.get("risk_level"),
                            "risk_summary": agent_structured.get("risk_summary", ""),
                            "detail": agent_structured.get("detail", ""),
                            "findings": agent_structured.get("findings", []),
                            "tools": [  # Evidence Chain: 该 Agent 调用了哪些工具
                                _tc.get("tool") for _tc in
                                (agent_result.get("agent_trace") or agent_result.get("tool_calls") or [])
                                if _tc.get("tool")
                            ],
                        })
                        trace_events.append({
                            "type": "agent", "agent_id": agent_id,
                            "round": rnd, "task": task,
                            "duration_ms": agent_result.get("duration_ms", 0),
                            "verdict": agent_structured.get("verdict"),
                        })

                        yield {
                            "type": "true_react_agent_result",
                            "round": rnd, "agent_id": agent_id,
                            "content": f"  [Agent] **{agent_id}** 分析完成\n",
                            "structured": agent_structured,
                            # 新增字段
                            "structured_result": agent_structured,
                            "agent_trace": agent_result.get("agent_trace", []),
                        }

                        # 结构化摘要（让 LLM 能理解 Agent 的裁决结果）
                        summary_parts = [f"[Agent {agent_id} 分析结果]"]
                        summary_parts.append(agent_output_text[:1000] if agent_output_text else "(无详细分析)")
                        if agent_structured:
                            summary_parts.append(f"[结构化裁决] verdict={agent_structured.get('verdict','?')}, "
                                                  f"confidence={agent_structured.get('confidence',0):.0%}, "
                                                  f"risk={agent_structured.get('risk_level','?')}")
                        agent_summary = "\n\n".join(summary_parts)

                        messages.append({
                            "role": "tool",
                            "tool_call_id": ac.call_id or f"route_{agent_id}",
                            "content": agent_summary,
                        })

            yield {
                "type": "true_react_round_complete",
                "round": rnd,
                "tool_count": len(tool_calls_only),
                "agent_count": len(agent_calls),
                "content": f"\n第 {rnd} 轮完成（工具={len(tool_calls_only)}, Agent={len(agent_calls)}）。\nLLM 将看到所有结果并继续指挥...\n",
            }

        # ═══════ 达到最大轮次 ═══════
        messages.append({
            "role": "user",
            "content": (
                "你已经进行了多轮分析。基于所有已获取的信息（包括工具结果和 Agent 分析结果），"
                "请给出最终的综合结论。如果信息不足以做出判断，请明确说明需要人工介入。"
            ),
        })

        # 达到最大轮次：同样强制结构化输出（JSON-first）
        agg = self._aggregate_confidence(collected_agent_results) if collected_agent_results else None
        # ── Decision Fusion（统一决策框架，v2.4） ──
        fusion_result = None
        evidence_packages = None
        risk_scorecard = None
        if collected_agent_results:
            fusion_result, evidence_packages, risk_scorecard = \
                self._run_fusion(collected_agent_results, target_ip)
            if risk_scorecard is None:
                risk_scorecard = self._score_risk({
                    "agent_results": collected_agent_results,
                    "ip": target_ip,
                    "event_history": self._load_event_history(target_ip),
                })

        final_result = await self._build_final_result(
            status="max_rounds",
            conversation_id=conversation_id,
            rounds=self.MAX_ROUNDS,
            total_tool_calls=total_tool_calls,
            total_agent_calls=total_agent_calls,
            messages=messages,
            last_content=last_round_content or "",
            agg=agg,
            risk_scorecard=risk_scorecard,
            agent_results=collected_agent_results,
            force_needs_human=True,
            fusion_result=fusion_result,
            evidence_packages=evidence_packages,
            target_ip=target_ip,
            task=text,
            template_type=template_type,
        )
        content_text = final_to_markdown(final_result)

        elapsed = (time.time() - start) * 1000
        yield {
            "type": "true_react_max_rounds",
            "rounds": self.MAX_ROUNDS,
            "total_tool_calls": total_tool_calls,
            "total_agent_calls": total_agent_calls,
            "content": f"  **达到最大轮次 {self.MAX_ROUNDS}，以下是综合结论:**\n\n{content_text}\n\n---\n> [警告] 达到最大分析轮次，建议人工复核\n",
            "summary": final_result.summary_text or content_text,
            "total_duration_ms": elapsed,
            "needs_human_intervention": True,
            "tool_call_history": self.engine.history.to_dict(),
            "confidence_aggregate": agg,
            "risk_scorecard": risk_scorecard,
            # 新增字段
            "structured_result": final_result.model_dump(mode="json"),
            "agent_trace": trace_events,
            "score": final_result.score,
        }
