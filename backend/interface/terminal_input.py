"""Async line editing for real terminals; no persistent command-history file."""
import os
import sys

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import DummyCompleter, WordCompleter
    from prompt_toolkit.history import InMemoryHistory
except ImportError:  # Allow older installations to keep using basic input.
    PromptSession = None


COMMANDS = (
    "/help", "/new", "/history", "/resume", "/agents", "/stats",
    "/model", "/export", "/auto", "/continue", "/cancel", "/clear", "/exit",
)


class TerminalInput:
    def __init__(self, **session_options):
        if PromptSession is None:
            raise RuntimeError("prompt-toolkit is not installed")
        self.completer = WordCompleter(COMMANDS, sentence=True)
        self.session = PromptSession(
            history=InMemoryHistory(),
            complete_while_typing=False,
            enable_history_search=True,
            **session_options,
        )

    async def read(self, continuation=False):
        label = "... > " if continuation else "你 > "
        message = label if os.getenv("NO_COLOR") is not None else [("ansicyan bold", label)]
        return await self.session.prompt_async(
            message,
            completer=DummyCompleter() if continuation else self.completer,
        )


def create_terminal_input():
    if PromptSession is None or not sys.stdin.isatty() or not sys.stdout.isatty():
        return None
    if os.getenv("TERM") == "dumb":
        return None
    return TerminalInput()
