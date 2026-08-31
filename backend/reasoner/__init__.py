"""
Reasoner — 统一推理引擎（简化版）

直接聚合 Agent 的结构化输出（verdict/confidence/evidence），
不再做文本正则解析 + 假设生成 + 贝叶斯更新的过度设计。

主要入口:
    from .reasoner import Reasoner
    reasoner = Reasoner()
    result = await reasoner.reason(query, agent_outputs)
    report = result["report"]  # 人类可读报告
"""

from .reasoner import Reasoner, ConflictRecord

__all__ = [
    "Reasoner",
    "ConflictRecord",
]
