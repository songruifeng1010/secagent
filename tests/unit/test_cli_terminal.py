"""终端行为回归：不初始化 Agent、不调用外部模型。"""
import asyncio
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from backend.interface.cli import SecAgentCLI


class TerminalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.cli = SecAgentCLI.__new__(SecAgentCLI)
        self.cli.console = None
        self.cli._json_mode = False
        self.cli._current_task = None
        self.cli._terminal_input = None
        self.cli.conversation_id = "cli-test"
        self.cli.repo = Mock()
        self.cli.repo.save_message = AsyncMock()
        self.cli._render_answer = Mock()

    async def consume(self, *events, json_mode=False):
        async def stream():
            for event in events:
                yield event
        return await self.cli._consume_stream(stream(), json_mode)

    async def test_final_answer_excludes_intermediate_analysis(self):
        result = await self.consume(
            {"type": "true_react_think_content", "content": "intermediate-only"},
            {"type": "stream", "content": "draft"},
            {"type": "true_react_complete", "content": "final answer", "response_mode": "plain_text"},
        )
        self.assertEqual(result[1], "final answer")
        self.cli._render_answer.assert_called_once_with("final answer", "plain_text")
        self.assertNotIn("intermediate-only", result[0])

    async def test_error_does_not_masquerade_as_success(self):
        result = await self.consume({"type": "error", "error": "provider unavailable"})
        self.assertIn("provider unavailable", result[1])

    async def test_fullscreen_event_handler_receives_stream_events(self):
        observed = []
        self.cli.event_handler = observed.append
        self.cli.render_enabled = False
        result = await self.consume(
            {"type": "stream", "content": "answer"},
            {"type": "true_react_complete", "content": "answer"},
        )
        self.assertEqual([item["type"] for item in observed], ["stream", "true_react_complete"])
        self.assertEqual(result[1], "answer")
        self.cli._render_answer.assert_not_called()

    async def test_json_does_not_render(self):
        await self.consume({"type": "true_react_complete", "content": "answer"}, json_mode=True)
        self.cli._render_answer.assert_not_called()

    async def test_live_terminal_stream_handles_markdown(self):
        from rich.console import Console
        capture = io.StringIO()
        self.cli.console = Console(file=capture, force_terminal=True, width=60)
        with patch("backend.interface.cli.sys.stdout.isatty", return_value=True), patch("backend.interface.cli.Live") as live:
            result = await self.consume(
                {"type": "true_react_agent_dispatch", "agent_id": "intel"},
                {"type": "stream", "content": "**hello**"},
                {"type": "true_react_complete", "content": "hello", "response_mode": "plain_text"},
            )
        self.assertEqual(result[1], "hello")
        live.return_value.start.assert_called_once()
        live.return_value.stop.assert_called_once()
        self.assertGreaterEqual(live.return_value.update.call_count, 2)

    async def test_export_never_overwrites_existing_file(self):
        self.cli.repo.get_messages = AsyncMock(return_value=[{"role": "user", "content": "hello"}])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "conversation.md"
            with redirect_stdout(io.StringIO()):
                await self.cli.cmd_export(str(path))
                original = path.read_text(encoding="utf-8")
                self.cli.repo.get_messages.return_value = []
                await self.cli.cmd_export(str(path))
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    async def test_resume_checks_owner_via_repository(self):
        self.cli.repo.get_conversation = AsyncMock(return_value=None)
        with redirect_stdout(io.StringIO()):
            await self.cli.cmd_resume("another-owner")
        self.assertEqual(self.cli.conversation_id, "cli-test")
        self.cli.repo.get_messages.assert_not_called()

    async def test_cancel_current_analysis_returns_to_caller(self):
        self.cli.load_history = AsyncMock(return_value=[])
        async def cancelled(*args, **kwargs):
            raise asyncio.CancelledError()
        self.cli._consume_stream = cancelled
        with redirect_stdout(io.StringIO()):
            await self.cli.run("test")
        self.assertIn("取消", self.cli.repo.save_message.call_args.kwargs["content"])

    async def test_timeout_awaits_cancelled_task(self):
        self.cli.load_history = AsyncMock(return_value=[])
        stopped = asyncio.Event()
        async def hanging(*args, **kwargs):
            try:
                await asyncio.sleep(10)
            finally:
                stopped.set()
        self.cli._consume_stream = hanging
        with patch("backend.interface.cli.PROCESS_TIMEOUT_SECONDS", 0.01), redirect_stdout(io.StringIO()):
            await self.cli.run("test")
        self.assertTrue(stopped.is_set())
        self.assertTrue(self.cli._current_task.done())

    async def test_multiline_interrupt_discards_partial_input(self):
        with patch("builtins.input", side_effect=["partial draft", KeyboardInterrupt]), redirect_stdout(io.StringIO()):
            self.assertEqual(await self.cli.read_multiline(), "")

    async def test_multiline_preserves_indentation(self):
        with patch("builtins.input", side_effect=["    code", "```"]):
            self.assertEqual(await self.cli.read_multiline(), "    code")


if __name__ == "__main__":
    unittest.main()
