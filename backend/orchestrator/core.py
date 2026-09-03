import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Optional, AsyncGenerator
from dataclasses import dataclass, field

from ..models.message import AgentMessage, MessageType, Task
from ..agents.base import BaseAgent
from ..tools.registry import ToolRegistry
from ..llm.provider import LLMFactory
from ..reasoner import Reasoner
from .react_loop import TrueReActLoop


@dataclass
class AgentInfo:
    name: str
    instance: BaseAgent
    description: str
    enabled: bool = True


class Orchestrator:
    def __init__(self, config: Optional[dict] = None, tools: Optional[ToolRegistry] = None):
        self.config = config or {}
        self.agent_id = self.config.get("agent_id", "orch-001")
        # 如果配置中包含 LLM 配置，则传进去
        raw_llm_cfg = self.config.get("llm", None) or {}
        # 配置属于调用方；构造编排器不能通过 pop 修改它。
        llm_cfg = dict(raw_llm_cfg) if isinstance(raw_llm_cfg, dict) else {}
        # 提取 fallback 配置（并防止修改原 dict）
        fallback_cfg = None
        if isinstance(llm_cfg, dict):
            fallback_cfg = llm_cfg.pop("fallback", None)
            llm_provider = llm_cfg.pop("provider", None)
        else:
            llm_provider = None
        # 显式 provider 优先于历史 DeepSeek 默认值，便于本地 Mock、Ollama
        # 及其他已配置运行时安全地生效。
        self.llm = (
            LLMFactory.get_provider(llm_provider, llm_cfg, fallback_cfg)
            if llm_provider
            else LLMFactory.get_deepseek(llm_cfg, fallback_cfg)
        )
        self.tools = tools or ToolRegistry()
        self.agents: dict[str, AgentInfo] = {}
        self.conversation_history: list[dict] = []
        self.active_tasks: dict[str, Task] = {}
        self.reasoner = Reasoner(llm=self.llm)
        self._agent_outputs: list[dict] = []

    # 指挥官（Orchestrator）只读工具白名单：
    # 处置类工具（firewall_manage 封禁等）不直接暴露给指挥官，
    # 必须通过路由到 responder-001 执行 —— 防止 LLM 自主误封禁。
    READ_ONLY_TOOLS = {
        "threat_intel", "geoip", "log_analyzer", "alert_filter",
        "cve_search", "ml_threat_detector",
    }

    def get_readonly_tools(self) -> ToolRegistry:
        """返回指挥官可直调的工具子集（只读，无处置能力）。"""
        sub = ToolRegistry()
        for name in self.READ_ONLY_TOOLS:
            t = self.tools.get(name)
            if t is not None:
                sub.register(t)
        return sub

    def register_agent(self, agent_id: str, name: str, instance: BaseAgent,
                        description: str = "", enabled: bool = True):
        self.agents[agent_id] = AgentInfo(
            name=name, instance=instance, description=description, enabled=enabled,
        )

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        info = self.agents.get(agent_id)
        return info.instance if info and info.enabled else None

    # ═══════════════════ 唯一处理入口 ═══════════════════

    async def process(self, text: str, history_messages: list = None) -> AsyncGenerator[dict, None]:
        """
        统一入口 — TrueReAct 循环（LLM Function Calling 驱动的 Think→Tool→Observe）

        参数:
            text: 用户当前输入
            history_messages: 历史对话消息列表，将在 system 后、当前消息前注入

        使用方式:
            async for chunk in orchestrator.process(text):
                await websocket.send_json(chunk)

            # 带历史:
            async for chunk in orchestrator.process(text, history_messages=history):
                await websocket.send_json(chunk)
        """
        loop = TrueReActLoop(self)
        async for chunk in loop.run(text, history_messages=history_messages):
            yield chunk

    # 向后兼容别名
    process_with_true_react = process

    # ═══════════════════ Agent 管理 ═══════════════════

    def get_agent_statuses(self) -> list[dict]:
        return [
            {
                "id": aid, "name": info.name, "description": info.description,
                "status": info.instance.status if hasattr(info.instance, "status") else "unknown",
                "enabled": info.enabled,
            }
            for aid, info in self.agents.items()
        ]

    def get_agent_runtime(self) -> list[dict]:
        return [
            {
                "agent": info.name, "agent_id": aid,
                "status": "running" if info.instance.status == "busy" else
                          "completed" if info.instance.stats.get("tasks_completed", 0) > 0 else "idle",
                "latency": info.instance.stats.get("last_duration_ms", 0),
                "tokens": info.instance.stats.get("last_tokens", 0),
                "total_tokens": info.instance.stats.get("total_tokens", 0),
                "total_tasks": info.instance.stats.get("tasks_completed", 0),
            }
            for aid, info in self.agents.items()
        ]

    def get_stats(self) -> dict:
        total = failed = 0
        for info in self.agents.values():
            total += info.instance.stats.get("tasks_completed", 0)
            failed += info.instance.stats.get("tasks_failed", 0)
        return {
            "total_tasks": total, "failed_tasks": failed,
            "agents_count": len(self.agents), "tools_count": self.tools.count(),
        }

    def get_auto_modules(self) -> dict:
        """获取自动模块引用（替代直接访问 _auto_modules 私有属性）"""
        return getattr(self, "_auto_modules", {})

    def get_config(self) -> dict:
        """获取运行时配置（替代直接访问 _config 私有属性）"""
        return getattr(self, "_config", {})

    def get_last_activity(self) -> dict:
        """获取各 Agent 最后活动时间（用于健康检查）"""
        activity = {}
        for aid, info in self.agents.items():
            inst = info.instance
            activity[aid] = {
                "status": inst.status,
                "last_duration_ms": inst.stats.get("last_duration_ms", 0),
                "total_tasks": inst.stats.get("tasks_completed", 0),
                "failed_tasks": inst.stats.get("tasks_failed", 0),
                "total_tokens": inst.stats.get("total_tokens", 0),
            }
        return activity

    # ═══════════════════ 别名：确保外部调用兼容 ═══════════════════

    # process 是唯一处理入口，以下保留为别名供旧代码兼容
    process_with_true_react = process
