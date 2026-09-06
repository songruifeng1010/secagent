import argparse

import pytest

from backend import cli_app
from backend.config.provider_profiles import ProviderProfileStore


@pytest.fixture(autouse=True)
def isolate_provider_runtime_environment(monkeypatch):
    """CLI onboarding 会直接激活档案；每个用例后必须恢复进程级路由。"""
    for key in (
        "SECAGENTX_ACTIVE_PROVIDER", "LLM_PROVIDER", "SECAGENTX_LLM_PROFILE",
        "SECAGENTX_LLM_PROVIDER_ID", "SECAGENTX_LLM_API_BASE",
        "SECAGENTX_LLM_MODEL", "SECAGENTX_LLM_AUTH_STYLE",
        "SECAGENTX_LLM_API_VERSION", "SECAGENTX_LLM_ALLOW_NO_KEY",
        "SECAGENTX_LLM_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


def test_noninteractive_mock_onboarding(tmp_path, monkeypatch):
    monkeypatch.setenv("SECAGENTX_HOME", str(tmp_path / "home"))

    result = cli_app.main([
        "onboard", "--provider", "mock", "--profile", "offline",
        "--non-interactive", "--accept-risk", "--skip-web",
    ])

    assert result == 0
    active = ProviderProfileStore().active()
    assert active.profile_id == "offline"
    assert active.protocol == "mock"


def test_noninteractive_onboarding_requires_explicit_risk_acceptance(tmp_path, monkeypatch):
    monkeypatch.setenv("SECAGENTX_HOME", str(tmp_path / "home"))
    result = cli_app.main([
        "onboard", "--provider", "mock", "--non-interactive", "--skip-web",
    ])
    assert result == 2
    assert not (tmp_path / "home" / "providers.json").exists()


def test_interactive_profile_reads_hidden_api_key(monkeypatch):
    """交互配置必须能够通过 getpass 安全读取未设置在环境中的 API Key。"""
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    answers = iter(["", ""])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    monkeypatch.setattr(cli_app.getpass, "getpass", lambda _prompt: "test-secret")
    args = argparse.Namespace(
        api_base="", model="", api_key_env="", non_interactive=False,
        profile="default", timeout=60.0,
    )

    profile, secret = cli_app._profile_from_answers(
        "deepseek", dict(cli_app.PROVIDER_PRESETS["deepseek"]), args,
    )

    assert profile.api_base == "https://api.deepseek.com/v1"
    assert profile.model == "deepseek-chat"
    assert profile.credential_type == "keyring"
    assert secret == "test-secret"


def test_ui_init_creates_clean_template(tmp_path):
    target = tmp_path / "custom-ui"
    assert cli_app.main(["ui", "init", str(target)]) == 0
    assert (target / "package.json").is_file()
    assert not (target / "node_modules").exists()
    assert not (target / "dist").exists()
    assert not any(target.glob(".npm-cache*"))


def test_ui_init_refuses_nonempty_target(tmp_path):
    target = tmp_path / "custom-ui"
    target.mkdir()
    (target / "mine.txt").write_text("keep", encoding="utf-8")
    assert cli_app.main(["ui", "init", str(target)]) == 1
    assert (target / "mine.txt").read_text(encoding="utf-8") == "keep"


def test_remote_bind_is_rejected_in_local_console_mode():
    args = argparse.Namespace(
        host="0.0.0.0", non_interactive=True,
        ui="", port=8000, no_open=True, log_level="info",
    )
    with pytest.raises(ValueError, match="只允许监听本机回环地址"):
        cli_app._serve(args, open_browser=False)


def test_environment_provider_is_visible_to_operations_commands(monkeypatch):
    monkeypatch.setenv("SECAGENTX_ACTIVE_PROVIDER", "mock")
    monkeypatch.setenv("SECAGENTX_LLM_API_BASE", "mock://local")
    monkeypatch.setenv("SECAGENTX_LLM_MODEL", "mock-llm")
    monkeypatch.setenv("SECAGENTX_LLM_ALLOW_NO_KEY", "true")

    profile, secret = cli_app._environment_profile()
    assert profile.protocol == "mock"
    assert profile.model == "mock-llm"
    assert secret == "local-no-key"


def test_tui_command_parser_supports_history_and_classic_fallback():
    args = cli_app.build_parser().parse_args(["tui", "--conv", "cli-existing"])
    assert args.command == "tui"
    assert args.conversation_id == "cli-existing"
    assert args.classic is False

    classic = cli_app.build_parser().parse_args(["tui", "--classic"])
    assert classic.classic is True
