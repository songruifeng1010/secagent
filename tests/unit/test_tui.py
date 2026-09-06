"""Full-screen TUI layout tests; no model or terminal is started."""

from unittest.mock import MagicMock, patch

from prompt_toolkit.input import DummyInput
from prompt_toolkit.output import DummyOutput

from backend.interface.tui import SecAgentTUI


def test_tui_builds_fullscreen_workspace_without_real_console():
    cli = MagicMock()
    cli.conversation_id = "cli-test"
    cli._current_task = None
    with patch("backend.interface.tui.SecAgentCLI", return_value=cli):
        tui = SecAgentTUI(input_source=DummyInput(), output=DummyOutput())

    assert tui.application.full_screen is True
    assert tui.composer.buffer is not None
    assert "Ctrl+N" in tui._status_text()[1][1]


def test_tui_completion_status_reports_agents_and_tools():
    text = SecAgentTUI._completion_status({
        "total_duration_ms": 1250,
        "total_agent_calls": 2,
        "total_tool_calls": 3,
    })
    assert "1250 ms" in text
    assert "2 Agent" in text
    assert "3 工具" in text
