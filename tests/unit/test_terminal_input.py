"""Exercise actual terminal key handling without a real console or external APIs."""
import asyncio
import unittest
from unittest.mock import patch

from backend.interface.terminal_input import PromptSession, TerminalInput, create_terminal_input


@unittest.skipIf(PromptSession is None, "prompt-toolkit not installed")
class TerminalInputTests(unittest.IsolatedAsyncioTestCase):
    async def enter(self, editor, keyboard, keys):
        pending = asyncio.create_task(editor.read())
        # History loading and completions are asynchronous in prompt-toolkit.
        await asyncio.sleep(0.1)
        keyboard.send_text(keys)
        await asyncio.sleep(0.1)
        keyboard.send_text("\r")
        return await asyncio.wait_for(pending, 3)

    async def test_arrow_recalls_previous_input(self):
        from prompt_toolkit.input import create_pipe_input
        from prompt_toolkit.output import DummyOutput
        with create_pipe_input() as keyboard:
            editor = TerminalInput(input=keyboard, output=DummyOutput())
            self.assertEqual(await self.enter(editor, keyboard, "test question"), "test question")
            self.assertEqual(await self.enter(editor, keyboard, "\x1b[A"), "test question")

    async def test_tab_completes_command(self):
        from prompt_toolkit.input import create_pipe_input
        from prompt_toolkit.output import DummyOutput
        with create_pipe_input() as keyboard:
            editor = TerminalInput(input=keyboard, output=DummyOutput())
            self.assertEqual(await self.enter(editor, keyboard, "/his\t"), "/history")

    def test_plain_question_and_arguments_are_not_command_completions(self):
        from prompt_toolkit.document import Document
        from prompt_toolkit.completion import CompleteEvent
        from prompt_toolkit.input import create_pipe_input
        from prompt_toolkit.output import DummyOutput
        with create_pipe_input() as keyboard:
            editor = TerminalInput(input=keyboard, output=DummyOutput())
            for text in ("what is SQL injection", "/resume cli-123"):
                self.assertEqual(list(editor.completer.get_completions(Document(text), CompleteEvent())), [])

    def test_non_tty_uses_basic_input(self):
        with patch("backend.interface.terminal_input.sys.stdin.isatty", return_value=False):
            self.assertIsNone(create_terminal_input())


if __name__ == "__main__":
    unittest.main()
