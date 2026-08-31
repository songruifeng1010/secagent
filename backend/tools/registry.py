from typing import Optional
from .base import BaseTool, ToolResult


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool):
        if not tool.name:
            raise ValueError(f"Tool must have a name: {type(tool).__name__}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_tools(self) -> list[BaseTool]:
        return list(self._tools.values())

    def to_openai_functions(self) -> list[dict]:
        return [t.to_openai_function() for t in self._tools.values()]

    def to_tool_list(self) -> list[dict]:
        return [t.to_tool_call() for t in self._tools.values()]

    async def execute(self, name: str, **kwargs) -> ToolResult:
        tool = self.get(name)
        if tool is None:
            return ToolResult(success=False, error=f"Tool not found: {name}")
        return await tool.execute(**kwargs)

    def count(self) -> int:
        return len(self._tools)

    def get_tools_for_llm(self) -> list[dict]:
        """获取 OpenAI 兼容的 tools 参数（供 LLM Function Calling 使用）"""
        return [t.to_openai_function() for t in self._tools.values()]

