"""Full-screen terminal interface for SecAgentX.

The TUI deliberately builds on prompt-toolkit, which is already a core runtime
dependency.  It shares the classic CLI's orchestrator and conversation store;
there is no second backend or incompatible history format.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from dataclasses import dataclass
from typing import Any

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import Frame, TextArea

from backend.interface.cli import SecAgentCLI


HELP = (
    "快捷键：Enter 发送 · Alt+Enter 换行 · Ctrl+N 新对话 · "
    "Ctrl+L 清屏 · Ctrl+C 取消分析 · Ctrl+Q 退出"
)


@dataclass
class ChatLine:
    role: str
    content: str


class SecAgentTUI:
    """A keyboard-first, full-screen terminal conversation workspace."""

    def __init__(
        self,
        conversation_id: str = "",
        *,
        input_source: Any = None,
        output: Any = None,
    ) -> None:
        self.cli = SecAgentCLI(conversation_id=conversation_id)
        self.cli.render_enabled = False
        self.cli.event_handler = self._handle_event
        self.messages: list[ChatLine] = []
        self.conversations: list[dict] = []
        self.streaming_text = ""
        self.busy = False
        self.status = "就绪"

        self.transcript = TextArea(
            text="",
            read_only=True,
            focusable=False,
            scrollbar=True,
            wrap_lines=True,
        )
        self.composer = TextArea(
            height=Dimension(min=3, max=7),
            multiline=True,
            prompt="你  ",
            style="class:composer",
        )
        self.history_control = FormattedTextControl(self._history_text, focusable=False)
        self.header_control = FormattedTextControl(self._header_text, focusable=False)
        self.status_control = FormattedTextControl(self._status_text, focusable=False)
        self.application = Application(
            layout=Layout(self._build_layout(), focused_element=self.composer),
            key_bindings=self._key_bindings(),
            style=self._style(),
            full_screen=True,
            mouse_support=False,
            input=input_source,
            output=output,
        )

    def _build_layout(self):
        history = Frame(
            Window(
                self.history_control,
                width=Dimension(min=24, preferred=29, max=34),
                wrap_lines=False,
            ),
            title="会话记录",
            style="class:sidebar",
        )
        conversation = Frame(self.transcript, title="安全对话", style="class:conversation")
        return HSplit([
            Window(self.header_control, height=2, style="class:header"),
            VSplit([history, conversation], padding=1, padding_char="│"),
            Frame(self.composer, title="输入问题", style="class:composer-frame"),
            Window(self.status_control, height=1, style="class:status"),
        ])

    def _key_bindings(self) -> KeyBindings:
        bindings = KeyBindings()

        @bindings.add("enter")
        def _send(event):
            self._schedule_send()

        @bindings.add("escape", "enter")
        def _newline(event):
            event.current_buffer.insert_text("\n")

        @bindings.add("c-n")
        def _new(event):
            if not self.busy:
                event.app.create_background_task(self._new_conversation())

        @bindings.add("c-l")
        def _clear(event):
            self.messages.clear()
            self.streaming_text = ""
            self._refresh_transcript()

        @bindings.add("c-c")
        def _cancel(event):
            if self.cli._current_task and not self.cli._current_task.done():
                self.cli._current_task.cancel()
                self.status = "正在取消分析…"
                event.app.invalidate()
            else:
                self.composer.buffer.reset()

        @bindings.add("c-q")
        def _quit(event):
            if self.cli._current_task and not self.cli._current_task.done():
                self.cli._current_task.cancel()
            event.app.exit()

        return bindings

    def _schedule_send(self) -> None:
        text = self.composer.text.strip()
        if not text or self.busy:
            return
        self.composer.buffer.reset()
        if text.startswith("/"):
            self.application.create_background_task(self._run_command(text))
        else:
            self.application.create_background_task(self._send(text))

    async def _send(self, text: str) -> None:
        self.busy = True
        self.status = "正在分析…  Ctrl+C 可取消"
        self.streaming_text = ""
        self.messages.append(ChatLine("你", text))
        self._refresh_transcript()
        try:
            result = await self.cli.run(text)
            answer = (result or {}).get("answer", "") or self.streaming_text
            self.messages.append(ChatLine("SecAgentX", answer or "未返回内容。"))
            self.status = self._completion_status((result or {}).get("stats") or {})
        except asyncio.CancelledError:
            self.messages.append(ChatLine("SecAgentX", "本次分析已取消。"))
            self.status = "已取消"
        except Exception as exc:
            self.messages.append(ChatLine("系统", f"分析失败：{exc}"))
            self.status = "执行失败"
        finally:
            self.busy = False
            self.streaming_text = ""
            await self._reload_history()
            self._refresh_transcript()

    async def _handle_event(self, event: dict) -> None:
        kind = event.get("type", "")
        labels = {
            "true_react_start": "开始分析",
            "true_react_think": "正在理解问题",
            "true_react_agent_route": "正在分配专业 Agent",
            "true_react_act": "正在执行安全工具",
            "true_react_round_complete": "正在汇总证据",
        }
        if kind == "stream":
            self.streaming_text += event.get("content") or ""
            self.status = "正在生成回答…  Ctrl+C 可取消"
            self._refresh_transcript()
        elif kind in labels:
            self.status = labels[kind] + "…  Ctrl+C 可取消"
        elif kind in ("true_react_tool_call", "true_react_tool_result"):
            name = event.get("tool_name") or "安全工具"
            self.status = f"{name} · {'完成' if kind.endswith('result') else '执行中'}"
        elif kind in ("true_react_agent_dispatch", "true_react_agent_result"):
            name = event.get("agent_id") or "Agent"
            self.status = f"{name} · {'完成' if kind.endswith('result') else '分析中'}"
        self.application.invalidate()

    async def _run_command(self, text: str) -> None:
        command, _, argument = text.partition(" ")
        command = command.lower()
        if command in ("/exit", "/quit"):
            self.application.exit()
            return
        if command == "/new":
            await self._new_conversation()
            return
        if command == "/clear":
            self.messages.clear()
            self._refresh_transcript()
            return
        if command == "/history":
            await self._reload_history()
            self.status = "历史会话已刷新；使用 /resume 会话ID 恢复"
        elif command == "/resume" and argument.strip():
            await self._resume(argument.strip())
        elif command == "/model":
            provider = os.getenv("SECAGENTX_ACTIVE_PROVIDER", "未配置") or "未配置"
            model = os.getenv("SECAGENTX_LLM_MODEL", "默认模型") or "默认模型"
            self.messages.append(ChatLine("系统", f"Provider：{provider}\n模型：{model}"))
        elif command == "/help":
            self.messages.append(ChatLine(
                "系统",
                HELP + "\n命令：/new /history /resume ID /model /clear /exit",
            ))
        else:
            self.messages.append(ChatLine("系统", "未知命令。输入 /help 查看可用命令。"))
        self._refresh_transcript()
        self.application.invalidate()

    async def _new_conversation(self) -> None:
        conversation_id = f"cli-{uuid.uuid4().hex[:8]}"
        await self.cli.repo.create_conversation(
            title=f"CLI对话 {conversation_id}", conversation_id=conversation_id,
        )
        self.cli.conversation_id = conversation_id
        self.messages.clear()
        self.status = "已新建对话"
        await self._reload_history()
        self._refresh_transcript()

    async def _resume(self, conversation_id: str) -> None:
        conversation = await self.cli.repo.get_conversation(conversation_id)
        if not conversation:
            self.status = "会话不存在或无权访问"
            return
        self.cli.conversation_id = conversation_id
        await self._load_messages()
        await self._reload_history()
        self.status = "已恢复历史对话"

    async def _load_messages(self) -> None:
        rows = await self.cli.repo.get_messages(self.cli.conversation_id, limit=200)
        self.messages = [
            ChatLine("你" if row.get("role") == "user" else "SecAgentX", row.get("content", ""))
            for row in rows if row.get("role") in ("user", "assistant") and row.get("content")
        ]
        self._refresh_transcript()

    async def _reload_history(self) -> None:
        self.conversations = await self.cli.repo.list_conversations(limit=20)
        self.application.invalidate()

    def _refresh_transcript(self) -> None:
        chunks: list[str] = []
        for item in self.messages:
            chunks.append(f"{item.role}\n{item.content.strip()}\n")
        if self.streaming_text:
            chunks.append(f"SecAgentX\n{self.streaming_text}\n")
        self.transcript.text = "\n".join(chunks) or (
            "欢迎使用 SecAgentX。\n\n"
            "可直接输入安全问题，知识问答与事件研判会自动采用合适的输出方式。"
        )
        self.transcript.buffer.cursor_position = len(self.transcript.text)
        self.application.invalidate()

    def _history_text(self):
        lines = []
        for conversation in self.conversations:
            current = conversation.get("id") == self.cli.conversation_id
            marker = "●" if current else " "
            title = conversation.get("title") or conversation.get("id", "未命名")
            lines.append(("class:history-current" if current else "class:history", f" {marker} {title[:24]}\n"))
        return lines or [("class:muted", " 暂无历史会话")]

    def _header_text(self):
        provider = os.getenv("SECAGENTX_ACTIVE_PROVIDER", "本地配置") or "本地配置"
        return [
            ("class:brand", " SecAgentX  "),
            ("class:header-subtitle", "AI 安全智能体"),
            ("class:header-meta", f"    {provider}  ·  {self.cli.conversation_id or '初始化中'}"),
        ]

    def _status_text(self):
        return [("class:status-ready" if not self.busy else "class:status-busy", f" {self.status}"),
                ("class:shortcut", "    " + HELP)]

    @staticmethod
    def _completion_status(stats: dict) -> str:
        duration = float(stats.get("total_duration_ms") or 0)
        tools = int(stats.get("total_tool_calls") or 0)
        agents = int(stats.get("total_agent_calls") or 0)
        return f"完成 · {duration:.0f} ms · {agents} Agent · {tools} 工具"

    @staticmethod
    def _style() -> Style:
        return Style.from_dict({
            "header": "bg:#111827 #dbeafe",
            "brand": "bold #60a5fa",
            "header-subtitle": "bold #f8fafc",
            "header-meta": "#64748b",
            "sidebar": "bg:#111827 #94a3b8",
            "conversation": "bg:#0b1019 #d7e1ef",
            "composer-frame": "bg:#111827 #93c5fd",
            "composer": "bg:#182235 #f8fafc",
            "status": "bg:#0f172a #94a3b8",
            "status-ready": "#4ade80",
            "status-busy": "#fbbf24",
            "shortcut": "#64748b",
            "history": "#94a3b8",
            "history-current": "bold #60a5fa",
            "muted": "#64748b",
            "frame.border": "#334155",
            "frame.label": "bold #94a3b8",
        })

    async def run(self) -> None:
        await self.cli._ensure_conversation()
        await self._load_messages()
        await self._reload_history()
        self._refresh_transcript()
        try:
            await self.application.run_async()
        finally:
            await self.cli.cleanup()


def run_tui(conversation_id: str = "") -> int:
    """Run the full-screen UI, validating terminal capabilities first."""
    if not sys.stdin.isatty() or not sys.stdout.isatty() or os.getenv("TERM") == "dumb":
        raise RuntimeError("TUI 需要交互式终端；脚本调用请使用 secagentx ask。")
    asyncio.run(SecAgentTUI(conversation_id=conversation_id).run())
    return 0


__all__ = ["SecAgentTUI", "run_tui"]
