"""
SessionMemory — 短期会话记忆（v2.4 M4）

维护当前会话的关键事实列表，支持：
  - remember: 写入结构化事实（IP/CVE/MITRE/裁决/置信度等）
  - recall:   按类型/关键词召回
  - 容量限制: 超限自动压缩（丢最旧）
  - 时间衰减: 旧记忆置信度打折（权重随时间衰减，防止误导）

设计纪律:
  - 记忆条目必须带置信度（来自确定性裁决，非 LLM 自拟）
  - 过期/衰减的记忆在召回时标注，注入 system prompt 时降低优先级
"""
import time
from typing import Optional

# 默认单会话记忆容量
DEFAULT_MAX_FACTS = 50
# 记忆半衰期（秒）— 超过后置信度衰减
DEFAULT_HALF_LIFE = 3600  # 1 小时


class SessionMemory:
    """会话工作记忆 — 线程内单实例，每个会话独立。"""

    def __init__(self, session_id: str = "", max_facts: int = DEFAULT_MAX_FACTS,
                 half_life: float = DEFAULT_HALF_LIFE):
        self.session_id = session_id
        self.max_facts = max_facts
        self.half_life = half_life
        self.facts: list[dict] = []  # 按时间升序

    def remember(self, content: str, category: str = "general",
                 confidence: float = 0.5, metadata: Optional[dict] = None) -> dict:
        """写入一条结构化记忆。category 建议: ip/ioc/cve/mitre/verdict/context。"""
        now = time.time()
        fact = {
            "id": f"{self.session_id}-{now:.0f}-{len(self.facts)}",
            "content": content,
            "category": category,
            "confidence": float(confidence),
            "created_at": now,
            "metadata": metadata or {},
        }
        # 去重：同一 category + 高相似内容（简单用内容前缀）-> 更新而非追加
        for existing in self.facts:
            if existing["category"] == category and existing["content"][:50] == content[:50]:
                existing["content"] = content
                existing["confidence"] = float(confidence)
                existing["created_at"] = now
                existing["metadata"] = metadata or {}
                return existing
        self.facts.append(fact)
        # 容量限制：超限丢最旧
        if len(self.facts) > self.max_facts:
            self.facts = self.facts[-self.max_facts:]
        return fact

    def recall(self, category: Optional[str] = None, keyword: str = "",
               limit: int = 10, with_decay: bool = True) -> list[dict]:
        """召回记忆。with_decay=True 时旧记忆置信度按半衰期衰减。"""
        now = time.time()
        results = []
        for f in self.facts:
            if category and f["category"] != category:
                continue
            if keyword and keyword.lower() not in f["content"].lower():
                continue
            item = dict(f)
            if with_decay:
                age = now - f["created_at"]
                decay = 0.5 ** (age / self.half_life) if self.half_life > 0 else 1.0
                item["effective_confidence"] = round(f["confidence"] * decay, 4)
            else:
                item["effective_confidence"] = f["confidence"]
            results.append(item)
        # 按有效置信度降序
        results.sort(key=lambda x: x["effective_confidence"], reverse=True)
        return results[:limit]

    def clear(self):
        self.facts = []

    def count(self) -> int:
        return len(self.facts)

    def to_context(self, limit: int = 8) -> list[dict]:
        """生成注入 LLM system prompt 的记忆上下文（仅高置信度 + 未衰减）。"""
        recalled = self.recall(with_decay=True, limit=limit)
        return [
            {
                "category": r["category"],
                "content": r["content"],
                "confidence": r["effective_confidence"],
            }
            for r in recalled
            if r["effective_confidence"] >= 0.3
        ]


__all__ = ["SessionMemory", "DEFAULT_MAX_FACTS", "DEFAULT_HALF_LIFE"]

