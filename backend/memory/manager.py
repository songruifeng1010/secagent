"""
MemoryManager — 记忆管理器（v2.4 M4）

统一读写三层记忆：
  1. SessionMemory   — 短期工作记忆（当前会话关键事实）
  2. EpisodicMemory  — 情景记忆（历史研判案例，experiences 表）
  3. SemanticMemory  — 语义记忆（高置信度事实向量沉淀）

核心职责:
  - build_context(text): 召回三层记忆，构造注入 system prompt 的记忆上下文
  - remember_from_result(...): 从一次研判结果提取关键事实并分层写入
  - 记忆注入带置信度 + 时间衰减，低置信度不注入（避免误导 LLM）

设计纪律（延续项目纪律）:
  - 所有记忆带置信度（来自确定性裁决），非 LLM 自拟
  - 语义记忆仅沉淀高置信度（≥0.7）事实，防止噪声污染
  - 记忆不可用（DB/Chroma 故障）→ 全部旁路，主链路永不阻断
"""
import logging
from typing import Optional

logger = logging.getLogger("secagentx.memory")

# 记忆注入模板：插入 system prompt 的记忆上下文
MEMORY_CONTEXT_TEMPLATE = """
## 历史记忆（带置信度，仅供参考，不作为唯一依据）
{items}

> 记忆标注: 每条记忆带置信度；旧记忆可能已衰减。若记忆与当前证据冲突，以当前证据为准。
"""


class MemoryManager:
    """三层记忆管理器。"""

    def __init__(self, session_memory: Optional[dict] = None,
                 episodic: Optional[object] = None,
                 semantic: Optional[object] = None):
        """
        参数:
          session_memory: dict {session_id: SessionMemory} 会话记忆注册表
          episodic: EpisodicMemory 实例（可空）
          semantic: SemanticMemory 实例（可空）
        """
        self._sessions = session_memory if session_memory is not None else {}
        self.episodic = episodic
        self.semantic = semantic

    # ═══════════════ 会话记忆 ═══════════════
    def get_session(self, session_id: str):
        """获取/创建会话记忆。"""
        if session_id not in self._sessions:
            from .session_memory import SessionMemory
            self._sessions[session_id] = SessionMemory(session_id=session_id)
        return self._sessions[session_id]

    def remember_session(self, session_id: str, content: str,
                         category: str = "general", confidence: float = 0.5,
                         metadata: Optional[dict] = None):
        try:
            self.get_session(session_id).remember(
                content, category=category, confidence=confidence, metadata=metadata,
            )
        except Exception as e:
            logger.debug("会话记忆写入失败（旁路）: %s", e)

    # ═══════════════ 记忆上下文构建 ═══════════════
    def build_context(self, text: str, session_id: str = "",
                      top_k: int = 6) -> str:
        """召回三层记忆，构造注入 system prompt 的记忆上下文。

        返回 markdown 段落（空 → 不注入）。
        """
        items = []

        # 1. 会话记忆（短期，当前会话）
        if session_id:
            try:
                for f in self.get_session(session_id).to_context(limit=top_k):
                    items.append(
                        f"- [会话·{f['category']}] {f['content']}（置信度 {f['confidence']:.0%}）"
                    )
            except Exception:
                pass

        # 2. 情景记忆（历史案例）
        if self.episodic is not None:
            try:
                import asyncio
                episodes = asyncio.get_event_loop().run_until_complete(
                    self.episodic.recall_similar(text, limit=3),
                )
                for ep in episodes:
                    items.append(
                        f"- [案例·{ep['scenario'][:40]}] 处置: {ep.get('outcome', '')[:80]}"
                    )
            except Exception:
                pass

        # 3. 语义记忆（长期向量）
        if self.semantic is not None:
            try:
                for m in self.semantic.recall(text, k=top_k):
                    items.append(
                        f"- [语义·{m['category']}] {m['content']}（置信度 {m['confidence']:.0%}）"
                    )
            except Exception:
                pass

        if not items:
            return ""
        return MEMORY_CONTEXT_TEMPLATE.format(items="\n".join(items[:top_k]))

    # ═══════════════ 研判结果沉淀 ═══════════════
    def remember_from_result(self, session_id: str, text: str,
                             agent_results: list = None,
                             risk_scorecard: dict = None,
                             verdict: dict = None) -> int:
        """从一次研判结果提取关键事实并分层写入。返回写入条数。"""
        count = 0
        try:
            # 1. 裁决级事实（高置信度 -> 沉淀）
            if verdict:
                v = verdict.get("verdict", "unknown")
                conf = float(verdict.get("confidence", 0.0) or 0.0)
                if v in ("malicious", "benign") and conf > 0:
                    self.remember_session(
                        session_id,
                        f"分析 '{text[:50]}' 裁决为 {v}（置信度 {conf:.0%}）",
                        category="verdict", confidence=conf,
                        metadata={"verdict": v, "source_text": text[:200]},
                    )
                    count += 1
                    # 高置信度恶意 -> 沉淀语义记忆（长期）
                    if self.semantic is not None and conf >= 0.7:
                        mid = self.semantic.add(
                            f"确认 {v}: '{text[:80]}'（置信度 {conf:.0%}）",
                            category="verdict", confidence=conf,
                            metadata={"verdict": v},
                        )
                        if mid:
                            count += 1

            # 2. Agent 裁决级事实
            for r in (agent_results or []):
                aid = r.get("agent_id", "")
                rv = r.get("verdict")
                rc = float(r.get("confidence") or 0.0)
                if rv in ("malicious", "benign") and rc >= 0.5:
                    self.remember_session(
                        session_id,
                        f"{aid} 裁决 {rv}（置信度 {rc:.0%}）",
                        category="agent_verdict", confidence=rc,
                        metadata={"agent_id": aid, "verdict": rv},
                    )
                    count += 1

            # 3. 风险评分级事实
            if risk_scorecard:
                score = risk_scorecard.get("risk_score")
                level = risk_scorecard.get("risk_level")
                if score is not None:
                    self.remember_session(
                        session_id,
                        f"风险评分 {score}（{level}）",
                        category="risk", confidence=0.8,
                        metadata={"score": score, "level": level},
                    )
                    count += 1
        except Exception as e:
            logger.debug("记忆沉淀失败（旁路）: %s", e)
        return count

    # ═══════════════ 查询/管理 ═══════════════
    def list_session_memory(self, session_id: str) -> list[dict]:
        return self.get_session(session_id).facts

    def clear_session(self, session_id: str):
        self.get_session(session_id).clear()

    async def stats(self) -> dict:
        """记忆统计（async — episodic.count 为 async 方法）。"""
        import asyncio
        episodic_count = 0
        semantic_count = 0
        if self.episodic is not None:
            try:
                episodic_count = await self.episodic.count()
            except Exception:
                episodic_count = 0
        if self.semantic is not None:
            try:
                semantic_count = self.semantic.count()
            except Exception:
                semantic_count = 0
        return {
            "sessions": len(self._sessions),
            "episodic_count": episodic_count,
            "semantic_count": semantic_count,
        }


__all__ = ["MemoryManager", "MEMORY_CONTEXT_TEMPLATE"]

