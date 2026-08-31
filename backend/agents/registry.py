"""
Agent 注册表 — 装饰器驱动的插件化 Agent 管理系统

使用方式:
    @register_agent(AgentMeta(agent_id="my-agent", name="我的Agent", ...))
    class MyAgent(BaseAgent):
        ...

    自动发现:
        from backend.agents.registry import discover_agents
        for agent_id, (meta, cls) in discover_agents().items():
            instance = cls(tools)
            orchestrator.register_agent(agent_id, meta.name, instance, meta.description)
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentMeta:
    """Agent 元数据 — 声明式注册所需信息"""
    agent_id: str                                  # 唯一 ID，如 "analyst-001"
    name: str = ""                                 # 显示名称，如 "安全分析师"
    description: str = ""                          # 功能描述
    capabilities: list[str] = field(default_factory=list)  # 能力关键词列表
    llm_provider: str = "deepseek"                 # 使用的 LLM 类型
    version: str = "1.0.0"                         # Agent 版本
    author: str = ""                               # 作者
    enabled: bool = True                           # 是否默认启用
    tags: list[str] = field(default_factory=list)  # 标签，便于分类检索

    def __post_init__(self):
        """自动填充 name（如未设置则从 agent_id 生成）"""
        if not self.name:
            self.name = self.agent_id


# 全局注册表
_registry: dict[str, tuple[AgentMeta, type]] = {}


def register_agent(meta: AgentMeta):
    """
    装饰器：声明式注册 Agent。

    用法:
        @register_agent(AgentMeta(agent_id="my-agent", ...))
        class MyAgent(BaseAgent):
            ...

    注册后，Agent 会被 discover_agents() 自动发现。
    """
    def decorator(cls):
        if meta.agent_id in _registry:
            import logging
            logging.getLogger("secagentx.registry").warning(
                f"Agent {meta.agent_id} 重复注册，将被覆盖"
            )
        _registry[meta.agent_id] = (meta, cls)
        return cls
    return decorator


def discover_agents(package: str = "backend.agents") -> dict[str, tuple[AgentMeta, type]]:
    """
    自动发现并加载所有使用 @register_agent 注册的 Agent。

    工作原理:
        1. 遍历指定的 Python 包（自动递归子模块）
        2. import 每个模块（触发 @register_agent 装饰器执行）
        3. 返回收集到的注册表

    参数:
        package: 要扫描的 Python 包名（默认为 "backend.agents"）

    返回:
        {agent_id: (AgentMeta, AgentClass), ...}
    """
    import importlib
    import pkgutil
    import logging

    logger = logging.getLogger("secagentx.registry")

    try:
        pkg = importlib.import_module(package)
    except ImportError as e:
        logger.warning(f"无法导入 Agent 包 {package}: {e}")
        return dict(_registry)

    discovered = 0
    for importer, modname, ispkg in pkgutil.iter_modules(pkg.__path__, prefix=f"{package}."):
        if modname.endswith("__init__") or modname.endswith("__pycache__"):
            continue
        try:
            importlib.import_module(modname)
            discovered += 1
        except Exception as e:
            logger.warning(f"加载 Agent 模块 {modname} 失败: {e}")

    if discovered:
        logger.info(f"Agent 自动发现: 扫描 {discovered} 个模块, 注册 {len(_registry)} 个 Agent")
    else:
        logger.info(f"Agent 自动发现: 未发现新 Agent 模块")

    return dict(_registry)


def get_registry() -> dict[str, tuple[AgentMeta, type]]:
    """获取当前注册表快照"""
    return dict(_registry)


def clear_registry():
    """清空注册表（主要用于测试）"""
    _registry.clear()


def get_agent_class(agent_id: str) -> Optional[type]:
    """根据 Agent ID 获取对应的类"""
    entry = _registry.get(agent_id)
    return entry[1] if entry else None


def get_agent_meta(agent_id: str) -> Optional[AgentMeta]:
    """根据 Agent ID 获取对应的元数据"""
    entry = _registry.get(agent_id)
    return entry[0] if entry else None


def list_agents() -> list[dict]:
    """列出所有注册的 Agent 元数据"""
    return [
        {
            "agent_id": meta.agent_id,
            "name": meta.name,
            "description": meta.description,
            "capabilities": meta.capabilities,
            "llm_provider": meta.llm_provider,
            "version": meta.version,
            "author": meta.author,
            "enabled": meta.enabled,
            "tags": meta.tags,
        }
        for meta, _ in _registry.values()
    ]

