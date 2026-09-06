"""
SecAgentX CLI — 多智能体协同安全检测终端

用法:
  python3 -m backend.interface.cli                 交互模式
  python3 -m backend.interface.cli --query "..."   一次性查询
  python3 -m backend.interface.cli --conv <id>     恢复历史会话

命令:
  /help       显示帮助
  /new        新建会话
  /history    查看历史会话；/resume ID 恢复指定会话
  /agents     查看 Agent 状态
  /stats      查看系统统计
  /model      查看当前模型
  /export     导出当前会话为 Markdown
  /auto       查看自动模块状态
  /continue   恢复上次会话
  /cancel     取消当前分析
  /clear      清屏
  /exit       退出

  ```...```  多行输入（首行 ``` 开始，``` 结束）
"""
import asyncio
import sys
import os
import json
import argparse
import signal
from contextlib import suppress
from pathlib import Path
from typing import Optional

# ─── 先将项目根目录加入 sys.path（必须在任何 backend 导入之前） ───
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ─── --json 模式：导入 backend 前把 stdout 指到 stderr ───
# 日志 console handler 在导入时绑定 sys.stdout，必须提前重定向才能保证 stdout 只有一行 JSON。
_ORIG_STDOUT = sys.stdout
if "--json" in sys.argv:
    sys.stdout = sys.stderr

# ─── 统一环境初始化 ───
os.environ["SECAGENTX_CLI_QUIET"] = "1"
from backend.utils.env import init_environment
init_environment()

from backend.main import load_config, init_application
from backend.utils.text import strip_md
from backend.storage.database import Repository
from backend.interface.terminal_input import create_terminal_input

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.spinner import Spinner
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - rich is a runtime dependency, fallback is defensive
    Console = Markdown = Panel = Table = Text = None
    RICH_AVAILABLE = False

# ─── 常量 ───
BANNER = """

                   SecAgentX · AI 安全智能体
           多智能体协同 · Agentic-RAG · 多厂商模型兼容

"""

HELP_TEXT = """可用命令:
  /help       显示帮助
  /new        新建会话
  /history    查看历史会话；/resume ID 恢复指定会话
  /agents     查看 Agent 状态（含 token 消耗和延迟）
  /stats      查看系统统计（含各 Agent 明细）
  /model      查看当前 Provider 和模型
  /export [文件] 导出当前会话为 Markdown
  /auto       查看自动模块（巡检/告警接入/升级通知）状态
  /continue   恢复上次会话（继续之前的对话）
  /cancel     取消当前正在执行的分析
  /clear      清屏
  /exit       退出

多行输入:
  ```          以 ``` 开头进入多行模式，再次输入 ``` 结束
  \"\"\"         也可以用 \"\"\"，用法同上

一次性查询:
  python3 -m backend.interface.cli --query "<问题>"

示例:
  python3 -m backend.interface.cli
  python3 -m backend.interface.cli -q "分析IP 45.33.32.156"
  python3 -m backend.interface.cli --conv cli-abc123def456
"""

MAX_HISTORY_MESSAGES = 20       # 默认历史消息数
MAX_HISTORY_TOKENS = 4000       # 按 token 估算时的上限
PROCESS_TIMEOUT_SECONDS = 120   # LLM 分析超时


# ─── 工具函数 ───

def c(text, color=""):
    if not sys.stdout.isatty() or os.getenv("NO_COLOR") is not None:
        return str(text)
    colors = {"green": "\033[92m", "yellow": "\033[93m", "blue": "\033[94m",
              "red": "\033[91m", "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"}
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def _estimate_tokens(text: str) -> int:
    """粗略估算 token 数：中英文混合场景按字符数/2"""
    return max(len(text) // 2, 1)


# ─── CLI 应用类 ───

class SecAgentCLI:
    """CLI 应用：管理资源生命周期 + 命令分发 + 流式输出"""

    def __init__(self, conversation_id: str = ""):
        self.config = load_config()
        self.orchestrator = init_application(self.config)
        self.db = Repository()
        from backend.storage.repositories.conversation_repo import ConversationRepository
        self.repo = ConversationRepository(
            self.db, owner_id=os.getenv("SECAGENTX_CLI_OWNER", "admin")
        )

        self.conversation_id = conversation_id or ""
        self._running = True
        self._current_task: Optional[asyncio.Task] = None
        self._json_mode = False  # --json 模式下抑制人类可读 stdout 输出
        self.console = Console(highlight=False, soft_wrap=True) if RICH_AVAILABLE else None
        self._terminal_input = None
        # Full-screen TUI reuses the same conversation/orchestrator lifecycle but
        # renders events itself. Classic CLI keeps these defaults unchanged.
        self.render_enabled = True
        self.event_handler = None

    # ═══════════════════ 终端渲染 ═══════════════════

    @property
    def _rich_mode(self) -> bool:
        """交互终端使用 Rich；JSON/管道模式继续保持纯文本协议。"""
        return bool(self.console and not self._json_mode and sys.stdout.isatty())

    def _render_banner(self, one_shot: bool = False) -> None:
        if self._rich_mode:
            title = Text("SecAgentX", style="bold bright_cyan")
            title.append("  ·  AI 安全智能体", style="bold white")
            subtitle = Text(
                "多智能体协同  ·  Agentic-RAG  ·  多厂商模型兼容\n"
                + ("一次性查询模式" if one_shot else "输入问题开始研判，/help 查看命令"),
                style="dim",
            )
            self.console.print(Panel(
                Text.assemble(title, "\n", subtitle),
                border_style="bright_blue",
                padding=(1, 2),
                expand=False,
            ))
            return
        print(BANNER)
        if one_shot:
            print(c("  一次性查询模式\n", "cyan"))
        else:
            print(HELP_TEXT)

    def _render_answer(self, content: str, response_mode: str = "") -> None:
        """将最终回答渲染成可读面板；机器模式不经过此路径。"""
        if not content:
            return
        if self._rich_mode:
            if response_mode == "plain_text":
                self.console.print(Markdown(content))
                return
            self.console.print(Panel(
                Markdown(content),
                title="SecAgentX · 最终研判",
                title_align="left",
                border_style="bright_blue",
                padding=(1, 2),
            ))
            return
        print(c(strip_md(content), "bold"))

    async def _render_prompt(self) -> str:
        if self._terminal_input is not None:
            return (await self._terminal_input.read()).strip()
        if self._rich_mode:
            return self.console.input("[bold bright_cyan]你[/] [dim]>[/] ").strip()
        return input(f"\n{c('你', 'cyan')} > ").strip()

    def _clear_terminal(self) -> None:
        if self._rich_mode:
            self.console.clear()
            self._render_banner()
            return
        print("\033[2J\033[H", end="", flush=True)
        print(BANNER)

    # ═══════════════════ 资源管理 ═══════════════════

    async def cleanup(self):
        """统一清理所有资源"""
        self._running = False

        # 取消正在执行的分析
        if self._current_task and not self._current_task.done():
            self._current_task.cancel()
            try:
                await self._current_task
            except (asyncio.CancelledError, Exception):
                pass

        # 关闭 ThreatIntelTool 的 httpx 连接池
        for tool in self.orchestrator.tools.list_tools():
            if hasattr(tool, "close"):
                try:
                    await tool.close()
                except Exception:
                    pass

        # 关闭 LLM 连接
        from backend.llm.provider import LLMFactory
        LLMFactory.clear()

        # 关闭数据库连接
        await self.db.close()

        # 取消后台自动模块任务
        auto_modules = self.orchestrator.get_auto_modules()
        for name, mod in auto_modules.items():
            if hasattr(mod, "stop"):
                try:
                    if hasattr(mod, "_running") and mod._running:
                        await mod.stop()
                except Exception:
                    pass
                if not self._json_mode and getattr(self, "render_enabled", True):
                    print(c(f"  [cli] 已停止 {name}", "yellow"))

    # ═══════════════════ 会话管理 ═══════════════════

    async def _ensure_conversation(self):
        """确保 conversation_id 有效，新建或恢复"""
        import uuid

        if self.conversation_id:
            # 恢复历史会话
            existing = await self.repo.get_conversation(self.conversation_id)
            if existing:
                if not self._json_mode and getattr(self, "render_enabled", True):
                    print(c(f"  [cli] 恢复会话: {self.conversation_id}", "blue"))
                messages = await self.repo.get_messages(self.conversation_id, limit=5)
                if messages and not self._json_mode and getattr(self, "render_enabled", True):
                    print(c(f"  [cli] 最近 {len(messages)} 条消息已加载", "blue"))
                return
            else:
                if not self._json_mode and getattr(self, "render_enabled", True):
                    print(c(f"  [cli] 会话 {self.conversation_id} 不存在，创建新会话", "yellow"))

        self.conversation_id = f"cli-{uuid.uuid4().hex[:8]}"
        await self.repo.create_conversation(
            title=f"CLI对话 {self.conversation_id}",
            conversation_id=self.conversation_id,
        )
        if not self._json_mode and getattr(self, "render_enabled", True):
            print(c(f"  [cli] 新会话: {self.conversation_id}", "green"))

    async def load_history(self) -> list[dict]:
        """加载历史消息，按 token 数动态调整条数"""
        messages = await self.repo.get_messages(self.conversation_id, limit=200)
        history = []
        total_tokens = 0

        # 从最新的消息开始取，直到达到 token 上限
        for msg in reversed(messages):
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role not in ("user", "assistant") or not content:
                continue
            tokens = _estimate_tokens(content)
            if total_tokens + tokens > MAX_HISTORY_TOKENS:
                break
            total_tokens += tokens
            history.insert(0, {"role": role, "content": content})
            if len(history) >= MAX_HISTORY_MESSAGES:
                break

        return history

    # ═══════════════════ 命令分发 ═══════════════════

    async def run(self, text: str, json_mode: bool = False):
        """
        执行一次分析（含超时保护）。

        json_mode=True 时：抑制人类可读打印，最终仅输出一行 JSON
        {"case": <conversation_id>, "decision": <verdict>, "score": <risk_score>}
        """
        history_messages = await self.load_history()

        # 保存用户消息
        await self.repo.save_message(
            conversation_id=self.conversation_id,
            role="user",
            content=text,
            agent_id="orchestrator",
        )

        if not json_mode and getattr(self, "render_enabled", True):
            print(c(f"\n  {'═' * 50}", "blue"))

        stream_buffer = ""
        assistant_content = ""
        total_stats = {}
        final_structured = None
        previous_sigint = signal.getsignal(signal.SIGINT)
        loop = asyncio.get_running_loop()
        def cancel_analysis(signum, frame):
            if self._current_task and not self._current_task.done():
                loop.call_soon_threadsafe(self._current_task.cancel)
        signal_installed = False
        try:
            signal.signal(signal.SIGINT, cancel_analysis)
            signal_installed = True
        except ValueError:
            pass  # 非主线程没有信号控制权。

        async def _process():
            async for chunk in self.orchestrator.process(text, history_messages=history_messages):
                yield chunk

        try:
            self._current_task = asyncio.create_task(
                self._consume_stream(_process(), json_mode=json_mode)
            )
            # 用 wait_for 加超时保护
            done, pending = await asyncio.wait(
                {self._current_task},
                timeout=PROCESS_TIMEOUT_SECONDS,
            )

            if self._current_task in pending:
                self._current_task.cancel()
                with suppress(asyncio.CancelledError):
                    await self._current_task
                if not json_mode and getattr(self, "render_enabled", True):
                    print(c(f"\n  [超时] 分析超过 {PROCESS_TIMEOUT_SECONDS}s，已取消", "red"))
                assistant_content = "分析超时，请简化问题后重试"
            else:
                result = self._current_task.result()
                if result:
                    stream_buffer, assistant_content, total_stats, final_structured = result

        except asyncio.CancelledError:
            if self._current_task:
                self._current_task.cancel()
                with suppress(asyncio.CancelledError):
                    await self._current_task
            if asyncio.current_task().cancelling():
                raise
            if not json_mode and getattr(self, "render_enabled", True):
                print("已取消当前分析，可以继续提问。")
            assistant_content = "本次分析已取消。"
        except asyncio.TimeoutError:
            if not json_mode and getattr(self, "render_enabled", True):
                print(c(f"\n  [超时] 分析超过 {PROCESS_TIMEOUT_SECONDS}s，已取消", "red"))
            assistant_content = "分析超时"
        except Exception as e:
            if not json_mode and getattr(self, "render_enabled", True):
                print(c(f"\n  [错误] {e}", "red"))
            assistant_content = f"分析异常: {e}"
        finally:
            if signal_installed:
                signal.signal(signal.SIGINT, previous_sigint)

        # 保存 LLM 回复
        if assistant_content:
            await self.repo.save_message(
                conversation_id=self.conversation_id,
                role="assistant",
                content=assistant_content,
                agent_id="orchestrator",
            )

        # --json 模式：输出机器可读 JSON（case / decision / score）
        if json_mode:
            _vd = (final_structured or {}).get("verdict") or {}
            _json_out = {
                "case": (final_structured or {}).get("conversation_id") or self.conversation_id,
                "decision": _vd.get("verdict", "unknown"),
                "score": (final_structured or {}).get("score", 0),
            }
            _ORIG_STDOUT.write(json.dumps(_json_out, ensure_ascii=False) + "\n")
            _ORIG_STDOUT.flush()
            return {
                "answer": assistant_content,
                "structured_result": final_structured,
                "stats": total_stats,
            }

        # 打印统计摘要
        if total_stats and getattr(self, "render_enabled", True):
            print()
            dur = total_stats.get("total_duration_ms", 0)
            tools = total_stats.get("total_tool_calls", 0)
            agents = total_stats.get("total_agent_calls", 0)
            print(c(f"  统计: {dur:.0f}ms | {tools} 工具调用 | {agents} Agent调用", "bold"))
        return {
            "answer": assistant_content,
            "structured_result": final_structured,
            "stats": total_stats,
        }

    async def _consume_stream(self, stream, json_mode: bool = False) -> tuple:
        """只将回答事件写入正文，中间执行事件更新同一行状态。"""
        buffer = ""
        answer = ""
        stats = {}
        structured = None
        response_mode = ""
        status = "正在分析 · Ctrl+C 取消"
        spinner = Spinner("dots", text=status) if self._rich_mode and not json_mode and getattr(self, "render_enabled", True) else None
        progress = Live(spinner, console=self.console, refresh_per_second=8, transient=True) if spinner else None
        if progress:
            progress.start()
        labels = {
            "true_react_start": "开始分析",
            "true_react_think": "正在分析",
            "true_react_agent_route": "分配专业 Agent",
            "true_react_act": "执行工具",
            "true_react_round_complete": "汇总结果",
        }
        try:
            async for chunk in stream:
                event_handler = getattr(self, "event_handler", None)
                if event_handler is not None:
                    callback_result = event_handler(chunk)
                    if asyncio.iscoroutine(callback_result):
                        await callback_result
                kind = chunk.get("type", "")
                if kind == "stream":
                    buffer += chunk.get("content") or ""
                    if progress:
                        spinner.update(text="正在生成回答 · Ctrl+C 取消")
                        progress.update(Group(Markdown(buffer), spinner))
                elif kind in ("true_react_complete", "true_react_max_rounds"):
                    structured = chunk.get("structured_result") or structured
                    response_mode = chunk.get("response_mode") or (structured or {}).get("response_mode", "")
                    answer = chunk.get("content") or chunk.get("summary") or buffer
                    stats = {key: chunk.get(key, 0) for key in (
                        "total_duration_ms", "total_tool_calls", "total_agent_calls",
                    )}
                elif kind == "error":
                    answer = "分析失败：" + str(chunk.get("content") or chunk.get("error") or "未知错误")
                elif progress:
                    status = labels.get(kind)
                    if kind in ("true_react_tool_call", "true_react_tool_result"):
                        status = f"工具 {chunk.get('tool_name', '')} · " + (
                            ("完成" if chunk.get("success") else "失败") if kind.endswith("result") else "执行中"
                        )
                    elif kind in ("true_react_agent_dispatch", "true_react_agent_result"):
                        status = f"Agent {chunk.get('agent_id', '')} · " + (
                            "完成" if kind.endswith("result") else "分析中"
                        )
                    if status:
                        spinner.update(text=Text(status + " · Ctrl+C 取消"))
                        progress.update(spinner)
        finally:
            if progress:
                progress.stop()
        answer = answer or buffer
        if not json_mode and getattr(self, "render_enabled", True):
            self._render_answer(answer, response_mode)
        return buffer, answer, stats, structured

    # ═══════════════════ 交互式命令处理 ═══════════════════

    async def cmd_agents(self):
        """查看 Agent 状态（含运行时统计）"""
        print(c("\n  Agent 状态:", "cyan"))
        print(c(f"  {'─' * 60}", "blue"))

        for s in self.orchestrator.get_agent_runtime():
            status_dot = "[G]" if s["status"] == "idle" else "[Y]" if s["status"] == "running" else "[R]"
            print(f"  {status_dot} [{s['agent_id']}] {s['agent']}")
            print(f"      状态: {s['status']} | "
                  f"延迟: {s['latency']}ms | "
                  f"Token: {s['total_tokens']} | "
                  f"任务: {s['total_tasks']}")

        # 显示各 Agent 的描述信息
        print(c(f"\n  Agent 职责:", "cyan"))
        for s in self.orchestrator.get_agent_statuses():
            print(f"    [{s['id']}] {s['name']}")
            print(f"      {s['description']}")

    async def cmd_stats(self):
        """查看系统统计"""
        stats = self.orchestrator.get_stats()
        activity = self.orchestrator.get_last_activity()

        print(c(f"\n  SecAgentX 系统统计:", "cyan"))
        print(c(f"  {'─' * 50}", "blue"))
        print(f"  Agent 数量:   {stats['agents_count']}")
        print(f"  工具数量:     {stats['tools_count']}")
        print(f"  总任务:       {stats['total_tasks']}")
        print(f"  失败任务:     {stats['failed_tasks']}")

        # 各 Agent 明细
        print(c(f"\n  Agent 运行明细:", "cyan"))
        for aid, info in activity.items():
            print(f"    [{aid}]")
            print(f"      状态: {info['status']}")
            print(f"      上次延迟: {info['last_duration_ms']}ms")
            print(f"      Token: {info['total_tokens']}")
            print(f"      任务: {info['total_tasks']} 成功 / {info['failed_tasks']} 失败")

        # 数据库状态
        print(c(f"\n  会话信息:", "cyan"))
        print(f"    当前会话ID: {self.conversation_id}")

    async def cmd_auto(self):
        """查看自动模块状态"""
        auto_modules = self.orchestrator.get_auto_modules()
        config = self.orchestrator.get_config()
        auto_cfg = config.get("auto_operation", {})

        print(c(f"\n  自动模块状态:", "cyan"))
        print(c(f"  {'─' * 50}", "blue"))

        enabled = auto_cfg.get("enabled", False)
        print(f"  总开关: {'✅ 已启用' if enabled else '❌ 已禁用'}")

        if not auto_modules:
            print(c(f"\n  (无活跃的自动模块)", "yellow"))
            return

        for name, mod in auto_modules.items():
            status = "运行中" if getattr(mod, "_running", False) else "已停止"
            print(f"  {status} | {name}")

            # 各模块特有信息
            if name == "ingestor" and hasattr(mod, "get_stats"):
                try:
                    ing_stats = mod.get_stats()
                    print(f"      已处理: {ing_stats.get('processed_count', 0)} | "
                          f"队列: {ing_stats.get('queue_size', 0)}")
                except Exception:
                    pass

            if name == "patrol" and hasattr(mod, "get_stats"):
                try:
                    pat_stats = mod.get_stats()
                    print(f"      巡检: {pat_stats.get('patrol_count', 0)} 次 | "
                          f"续封: {pat_stats.get('renew_count', 0)} 次")
                except Exception:
                    pass

            if name == "escalator" and hasattr(mod, "get_status"):
                try:
                    channels = mod.get_status()
                    active = [s["type"] for s in channels if s.get("enabled")]
                    print(f"      通知通道: {', '.join(active) if active else '仅控制台'}")
                except Exception:
                    pass

    async def cmd_continue(self):
        """恢复最近的历史会话"""
        conversations = await self.repo.list_conversations(limit=10)
        if not conversations:
            print(c("  (无历史会话)", "yellow"))
            return

        # 找到最近一次非当前的会话
        for conv in conversations:
            if conv["id"] != self.conversation_id:
                self.conversation_id = conv["id"]
                print(c(f"  已切换到会话: {self.conversation_id}", "green"))
                messages = await self.repo.get_messages(self.conversation_id, limit=3)
                if messages:
                    print(c(f"  最近消息:", "blue"))
                    for msg in messages[-3:]:
                        role = "你" if msg["role"] == "user" else "AI"
                        content = msg["content"][:80] + ("..." if len(msg["content"]) > 80 else "")
                        print(f"    [{role}] {content}")
                return

        print(c("  (没有其他历史会话)", "yellow"))

    async def cmd_new(self):
        """创建一个全新的 CLI 会话，不覆盖已有历史。"""
        import uuid

        self.conversation_id = f"cli-{uuid.uuid4().hex[:8]}"
        await self.repo.create_conversation(
            title=f"CLI对话 {self.conversation_id}",
            conversation_id=self.conversation_id,
        )
        if self._rich_mode:
            self.console.print(Panel(
                f"当前会话：{self.conversation_id}",
                title="新建会话",
                border_style="green",
                expand=False,
            ))
        else:
            print(c(f"  新会话: {self.conversation_id}", "green"))

    async def cmd_history(self):
        """以紧凑表格显示当前 CLI 用户的历史会话。"""
        conversations = await self.repo.list_conversations(limit=20)
        if self._rich_mode:
            table = Table(title="历史会话", border_style="blue", expand=False)
            table.add_column("当前", justify="center", width=5)
            table.add_column("会话 ID", overflow="fold")
            table.add_column("标题", min_width=24, max_width=48)
            table.add_column("消息", justify="right", width=6)
            table.add_column("更新时间", width=26)
            for conv in conversations:
                table.add_row(
                    "●" if conv["id"] == self.conversation_id else "",
                    Text(conv["id"]),
                    Text(conv.get("title") or conv["id"]),
                    str(conv.get("message_count", 0)),
                    conv.get("updated_at", ""),
                )
            self.console.print(table)
            return
        if not conversations:
            print(c("  (无历史会话)", "yellow"))
            return
        for conv in conversations:
            marker = "*" if conv["id"] == self.conversation_id else " "
            print(f" {marker} {conv['id']} | {conv.get('title') or conv['id']} | {conv.get('updated_at', '')}")

    async def cmd_resume(self, conversation_id: str):
        conversation = await self.repo.get_conversation(conversation_id)
        if not conversation:
            print("会话不存在或无权访问。")
            return
        self.conversation_id = conversation_id
        print(f"已恢复：{conversation.get('title') or conversation_id}")
        for msg in await self.repo.get_messages(conversation_id, limit=500):
            if msg.get("role") in ("user", "assistant"):
                if self._rich_mode:
                    self.console.print("你" if msg["role"] == "user" else "SecAgentX", style="bold cyan")
                    self.console.print(Markdown(msg.get("content", "")))
                else:
                    print(f"{msg['role']}: {msg.get('content', '')}")

    async def cmd_model(self):
        """显示当前运行时 Provider，不输出 API Key。"""
        provider = os.getenv("SECAGENTX_ACTIVE_PROVIDER", "") or "未配置"
        model = os.getenv("SECAGENTX_LLM_MODEL", "")
        if not model:
            llm = self.config.get("llm", {}) if isinstance(self.config, dict) else {}
            provider_cfg = llm.get(provider, {}) if isinstance(llm, dict) else {}
            model = provider_cfg.get("model", "默认模型") if isinstance(provider_cfg, dict) else "默认模型"
        text = f"Provider: {provider}\n模型: {model}\n会话: {self.conversation_id}"
        if self._rich_mode:
            self.console.print(Panel(text, title="当前运行时", border_style="cyan", expand=False))
        else:
            print(c("\n  当前运行时:", "cyan"))
            print(f"  Provider: {provider}\n  模型: {model}\n  会话: {self.conversation_id}")

    async def cmd_export(self, target: str = ""):
        """导出当前会话的用户问题和最终回答。"""
        messages = await self.repo.get_messages(self.conversation_id, limit=500)
        path = Path(target).expanduser() if target else Path(f"secagentx-{self.conversation_id}.md")
        lines = [f"# SecAgentX 会话 {self.conversation_id}", ""]
        for msg in messages:
            role = "用户" if msg.get("role") == "user" else "SecAgentX"
            lines.extend([f"## {role}", "", msg.get("content", ""), ""])
        try:
            with path.open("x", encoding="utf-8") as output:
                output.write("\n".join(lines))
        except FileExistsError:
            print("文件已存在，请指定新的导出文件名。")
            return
        except OSError as exc:
            print(f"导出失败：{exc}")
            return
        if self._rich_mode:
            self.console.print(f"已导出：{path}", style="green")
        else:
            print(c(f"  已导出: {path}", "green"))

    # ═══════════════════ 多行输入 ═══════════════════

    async def read_multiline(self) -> str:
        """读取多行输入（以 ``` 或 \"\"\" 包裹）"""
        lines = []
        while True:
            try:
                line = await self._terminal_input.read(continuation=True) if self._terminal_input else input()
            except (EOFError, KeyboardInterrupt):
                print("\n已取消多行输入，未发送。")
                return ""
            if line.strip() in ("```", '"""'):
                return "\n".join(lines)
            lines.append(line)

    # ═══════════════════ 主循环 ═══════════════════

    async def interactive_loop(self):
        """交互式主循环"""
        self._render_banner()
        self._terminal_input = create_terminal_input()

        await self._ensure_conversation()

        while self._running:
            try:
                first_line = await self._render_prompt()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not first_line:
                continue

            # ─── 过滤误粘贴的 shell 命令 ───
            if first_line.startswith(("python3", "/usr/bin/python", "python ", "sudo ", "cd ", "ls ", "cat ", "grep ")):
                print(c(f"  你已在 CLI 中，无需重复启动命令", "yellow"))
                print(c(f"  ─ 想恢复历史会话？输入 /continue", "blue"))
                print(c(f"  ─ 想退出？输入 /exit 回到终端，再执行 shell 命令", "blue"))
                continue

            # 多行输入模式
            if first_line in ("```", '"""'):
                print(c("  (多行模式，输入 ``` 或 \"\"\" 结束)", "yellow"))
                multiline = await self.read_multiline()
                if not multiline:
                    continue
                user_input = multiline
            else:
                user_input = first_line

            # ─── 命令处理 ───
            if user_input == "/exit":
                break
            elif user_input == "/help":
                if self._rich_mode:
                    self.console.print(Panel(HELP_TEXT, title="可用命令", border_style="blue", expand=False))
                else:
                    print(HELP_TEXT)
                continue
            elif user_input == "/new":
                await self.cmd_new()
                continue
            elif user_input == "/history":
                await self.cmd_history()
                continue
            elif user_input.startswith("/resume "):
                await self.cmd_resume(user_input.split(maxsplit=1)[1])
                continue
            elif user_input == "/model":
                await self.cmd_model()
                continue
            elif user_input == "/export" or user_input.startswith("/export "):
                await self.cmd_export(user_input[len("/export"):].strip())
                continue
            elif user_input == "/agents":
                await self.cmd_agents()
                continue
            elif user_input == "/stats":
                await self.cmd_stats()
                continue
            elif user_input == "/auto":
                await self.cmd_auto()
                continue
            elif user_input == "/continue":
                await self.cmd_continue()
                continue
            elif user_input == "/cancel":
                if self._current_task and not self._current_task.done():
                    self._current_task.cancel()
                    print(c("  [cancel] 已取消当前分析", "yellow"))
                else:
                    print(c("  (当前无正在执行的分析)", "yellow"))
                continue
            elif user_input == "/clear":
                self._clear_terminal()
                continue
            elif user_input.startswith("/"):
                print(c(f"  未知命令: {user_input}，输入 /help 查看帮助", "red"))
                continue

            # ─── 执行分析 ───
            await self.run(user_input)

        if self._rich_mode:
            self.console.print("再见！", style="bright_cyan")
        else:
            print(c("\n再见！", "cyan"))

    async def run_once(self, query: str, json_mode: bool = False):
        """一次性查询模式"""
        self._json_mode = json_mode
        if not json_mode:
            self._render_banner(one_shot=True)
        await self._ensure_conversation()
        await self.run(query, json_mode=json_mode)


# ═══════════════════ 入口 ═══════════════════

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SecAgentX · AI 安全智能体 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 -m backend.interface.cli                    交互模式
  python3 -m backend.interface.cli -q "分析这个IP"     一次性查询
  python3 -m backend.interface.cli -q "..." --json    输出机器可读 JSON（供脚本/CI）
  python3 -m backend.interface.cli --conv cli-xxx      恢复会话
        """,
    )
    parser.add_argument("-q", "--query", help="一次性查询（非交互模式）")
    parser.add_argument("--json", action="store_true",
                        help="一次性查询输出机器可读 JSON: {\"case\",\"decision\",\"score\"}")
    parser.add_argument("--conv", "--conversation", dest="conversation_id",
                        help="恢复指定会话ID")
    return parser.parse_args()


def _setup_signal_handlers(cli: SecAgentCLI, loop: asyncio.AbstractEventLoop):
    """注册信号处理，确保退出时清理资源"""
    def _signal_handler():
        print(c("\n\n  正在清理资源...", "yellow"))
        asyncio.ensure_future(cli.cleanup(), loop=loop)
        loop.stop()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _signal_handler)
    except (ValueError, NotImplementedError):
        # Windows 或某些环境不支持 add_signal_handler
        pass


def main():
    args = _parse_args()

    async def _main():
        cli = SecAgentCLI(conversation_id=args.conversation_id or "")

        try:
            if args.query:
                await cli.run_once(args.query, json_mode=args.json)
            else:
                await cli.interactive_loop()
        finally:
            await cli.cleanup()

    asyncio.run(_main())


if __name__ == "__main__":
    main()
