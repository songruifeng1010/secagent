"""
Orchestrator — 总调度引擎（精简版）

唯一入口:
    from .core import Orchestrator
    orch = Orchestrator(config, tools)
    async for chunk in orch.process(text):
        ...
"""

from .core import Orchestrator, AgentInfo
from .react_loop import TrueReActLoop

__all__ = [
    "Orchestrator", "AgentInfo",
    "TrueReActLoop",
]
