"""SecAgentX 统一命令入口。

首次运行进入 onboarding；配置完成后，裸命令进入终端对话。
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from backend.config.provider_profiles import (
    PROVIDER_PRESETS,
    CredentialStore,
    CredentialStoreError,
    ProviderProfile,
    ProviderProfileStore,
    activate_profile,
)
from backend.config.runtime_settings import RuntimeSettingsStore
from backend.runtime_assets import config_path, frontend_dir, frontend_dist, resource_root

PROJECT_ROOT = resource_root()


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("secagentx")
    except Exception:
        return "3.1.0"


def _has_legacy_provider() -> bool:
    return bool(
        os.getenv("SECAGENTX_ACTIVE_PROVIDER")
        or os.getenv("DEEPSEEK_API_KEY")
        or os.getenv("QWEN_API_KEY")
        or os.getenv("LLM_PROVIDER", "").lower() == "mock"
    )


def _environment_profile() -> tuple[Optional[ProviderProfile], str]:
    """把 Docker/CI 环境变量转换为仅驻留内存的 Provider 档案。"""
    protocol = os.getenv("SECAGENTX_ACTIVE_PROVIDER", "").strip().lower()
    if protocol:
        allow_no_key = os.getenv("SECAGENTX_LLM_ALLOW_NO_KEY", "false").lower() in (
            "1", "true", "yes",
        )
        secret = os.getenv("SECAGENTX_LLM_API_KEY", "")
        return ProviderProfile(
            profile_id="environment",
            provider_id=os.getenv("SECAGENTX_LLM_PROVIDER_ID", protocol),
            label="环境变量 Provider",
            protocol=protocol,
            api_base=os.getenv("SECAGENTX_LLM_API_BASE", "mock://local" if protocol == "mock" else ""),
            model=os.getenv("SECAGENTX_LLM_MODEL", "mock-llm" if protocol == "mock" else ""),
            credential_type="env",
            credential_ref="SECAGENTX_LLM_API_KEY",
            env_key="SECAGENTX_LLM_API_KEY",
            auth_style=os.getenv("SECAGENTX_LLM_AUTH_STYLE", "bearer"),
            api_version=os.getenv("SECAGENTX_LLM_API_VERSION", ""),
            requires_api_key=not allow_no_key,
        ), secret or ("local-no-key" if allow_no_key else "")

    legacy = os.getenv("LLM_PROVIDER", "").strip().lower()
    if legacy in ("deepseek", "qwen", "mock"):
        env_key = f"{legacy.upper()}_API_KEY" if legacy != "mock" else ""
        secret = os.getenv(env_key, "") if env_key else "local-no-key"
        preset = PROVIDER_PRESETS.get(legacy, PROVIDER_PRESETS["mock"])
        return ProviderProfile(
            profile_id="environment", provider_id=legacy, label="环境变量 Provider",
            protocol=legacy, api_base=preset["api_base"], model=preset["model"],
            credential_type="env", credential_ref=env_key, env_key=env_key,
            requires_api_key=legacy != "mock",
        ), secret
    return None, ""


def _input(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def _confirm(prompt: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    value = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes", "1", "true", "是")


def _select_provider() -> tuple[str, dict]:
    entries = list(PROVIDER_PRESETS.items())
    print("\n可用模型 Provider：")
    for index, (_, preset) in enumerate(entries, 1):
        print(f"  {index:>2}. {preset['label']}")
    while True:
        raw = input("请选择编号: ").strip()
        try:
            selected = entries[int(raw) - 1]
            return selected[0], dict(selected[1])
        except (ValueError, IndexError):
            print("输入无效，请输入列表中的编号。")


def _profile_from_answers(provider_id: str, preset: dict, args: argparse.Namespace) -> tuple[ProviderProfile, str]:
    api_base = args.api_base or preset.get("api_base", "")
    model = args.model or preset.get("model", "")
    if not args.non_interactive:
        api_base = _input("API Base URL", api_base)
        model = _input("模型 ID", model)
    if not api_base:
        raise ValueError("API Base URL 不能为空")
    if not model:
        raise ValueError("模型 ID 不能为空")

    env_key = args.api_key_env or preset.get("env_key", "")
    requires_key = preset.get("requires_api_key", True)
    secret = os.getenv(env_key, "") if env_key else ""
    credential_type = "env" if secret else "keyring"
    credential_ref = env_key if secret else f"provider:{args.profile}"
    if requires_key and not secret:
        if args.non_interactive:
            raise ValueError(f"非交互模式要求环境变量 {env_key or 'SECAGENTX_LLM_API_KEY'}")
        secret = getpass.getpass("API Key（输入不会回显）: ").strip()
        if not secret:
            raise ValueError("API Key 不能为空")

    profile = ProviderProfile(
        profile_id=args.profile,
        provider_id=provider_id,
        label=preset["label"],
        protocol=preset["protocol"],
        api_base=api_base,
        model=model,
        credential_type=credential_type,
        credential_ref=credential_ref,
        env_key=env_key,
        auth_style=preset.get("auth_style", "bearer"),
        api_version=preset.get("api_version", ""),
        requires_api_key=requires_key,
        timeout_seconds=float(args.timeout),
    )
    return profile, secret


async def _verify_profile(profile: ProviderProfile, secret: str) -> str:
    from backend.llm.provider import build_provider

    provider = build_provider(
        profile.protocol,
        profile.runtime_config(secret or "local-no-key"),
        use_runtime_profile=False,
    )
    try:
        response = await asyncio.wait_for(
            provider.chat([
                {"role": "system", "content": "You are a connection test. Reply with exactly: SECAGENTX_OK"},
                {"role": "user", "content": "ping"},
            ]),
            timeout=profile.timeout_seconds,
        )
        if not response.content.strip():
            raise RuntimeError("Provider 返回了空响应")
        return response.content.strip()[:120]
    finally:
        await provider.close()


def _configure_web_credentials(non_interactive: bool = False) -> None:
    store = RuntimeSettingsStore()
    if store.web_ready():
        return
    if non_interactive or not sys.stdin.isatty():
        raise RuntimeError(
            "Web 首次启动需要管理员凭据。请运行 secagentx onboard，"
            "或设置 SECAGENTX_PASSWORD 和 SECAGENTX_JWT_SECRET。"
        )
    print("\n配置 Web 管理员（密码不会写入明文配置）")
    password = getpass.getpass("管理员密码（至少 12 字符）: ")
    confirm = getpass.getpass("再次输入管理员密码: ")
    if password != confirm:
        raise ValueError("两次密码输入不一致")
    store.configure_web_credentials(password)
    store.activate()
    print("Web 管理员凭据已安全保存。")


def cmd_onboard(args: argparse.Namespace) -> int:
    if not args.accept_risk and args.non_interactive:
        print("非交互 onboarding 必须显式传入 --accept-risk。", file=sys.stderr)
        return 2
    if not args.non_interactive:
        print(f"\nSecAgentX {_version()} 首次配置")
        print("安全提示：Agent 可调用安全工具；自动处置默认关闭，生产启用前必须校验白名单。")
        if not _confirm("我已理解并继续", True):
            return 1

    provider_id, preset = (
        (args.provider, dict(PROVIDER_PRESETS[args.provider]))
        if args.provider else _select_provider()
    )
    try:
        profile, secret = _profile_from_answers(provider_id, preset, args)
        print(f"正在验证 {profile.label} / {profile.model} ...")
        result = asyncio.run(_verify_profile(profile, secret))
        print(f"连接验证成功：{result}")

        store = ProviderProfileStore()
        if profile.credential_type == "env":
            store.put(profile, api_key="", make_active=True)
        else:
            store.put(profile, api_key=secret, make_active=True)
        activate_profile(profile, secret or store.get_secret(profile))
        print(f"已保存活动 Provider：{profile.profile_id} ({profile.label})")

        if not args.skip_web and not args.non_interactive and _confirm("现在配置 Web 管理员", True):
            _configure_web_credentials()
        print("\n配置完成。运行 secagentx 进入 CLI，或运行 secagentx dashboard 打开 Web 控制台。")
        return 0
    except (ValueError, CredentialStoreError, OSError, RuntimeError) as exc:
        print(f"配置失败：{exc}", file=sys.stderr)
        print("原有活动 Provider 未被覆盖。", file=sys.stderr)
        return 1


async def _run_chat(query: str = "", json_mode: bool = False, conversation_id: str = "") -> None:
    from backend.interface.cli import SecAgentCLI

    cli = SecAgentCLI(conversation_id=conversation_id)
    try:
        if query:
            await cli.run_once(query, json_mode=json_mode)
        else:
            await cli.interactive_loop()
    finally:
        await cli.cleanup()


def cmd_chat(args: argparse.Namespace) -> int:
    if not ProviderProfileStore().active() and not _has_legacy_provider():
        if sys.stdin.isatty():
            result = cmd_onboard(_onboard_defaults())
            if result:
                return result
        else:
            print("尚未配置模型 Provider，请先运行 secagentx onboard。", file=sys.stderr)
            return 2
    asyncio.run(_run_chat(args.query or "", args.json, args.conversation_id or ""))
    return 0


def _wait_and_open(url: str) -> None:
    health_url = url.rstrip("/") + "/api/health"
    for _ in range(120):
        try:
            with urllib.request.urlopen(health_url, timeout=1) as response:
                if response.status < 500:
                    webbrowser.open(url)
                    return
        except Exception:
            time.sleep(0.25)


def _serve(args: argparse.Namespace, open_browser: bool) -> int:
    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    if args.host.strip().lower() not in loopback_hosts and not args.allow_remote:
        raise ValueError(
            "拒绝默认暴露到远程网络；如已配置防火墙、反向代理和 TLS，"
            "请显式添加 --allow-remote"
        )
    _configure_web_credentials(non_interactive=args.non_interactive)
    if getattr(args, "ui", ""):
        ui_path = Path(args.ui).expanduser().resolve()
        if not (ui_path / "index.html").is_file():
            raise FileNotFoundError(f"前端构建目录缺少 index.html: {ui_path}")
        os.environ["SECAGENTX_FRONTEND_DIST"] = str(ui_path)
    os.environ["SECAGENTX_HOST"] = args.host
    os.environ["SECAGENTX_PORT"] = str(args.port)
    if open_browser and not args.no_open:
        url = f"http://{args.host if args.host not in ('0.0.0.0', '::') else '127.0.0.1'}:{args.port}"
        threading.Thread(target=_wait_and_open, args=(url,), daemon=True).start()
        print(f"Web 控制台：{url}")
    from backend.interface.api_server import create_app
    import uvicorn

    uvicorn.run(create_app(), host=args.host, port=args.port, log_level=args.log_level)
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    store = ProviderProfileStore()
    profile = store.active()
    env_profile, env_secret = _environment_profile()
    effective_profile = profile or env_profile
    runtime = RuntimeSettingsStore()
    from backend.storage.database import _is_postgres, get_sqlite_path
    db_url = os.getenv("DATABASE_URL", "") if _is_postgres() else str(get_sqlite_path())
    frontend = frontend_dist()
    print(f"SecAgentX {_version()}")
    print(f"配置目录: {store.path.parent}")
    print(f"活动 Provider: {effective_profile.label + ' / ' + effective_profile.model if effective_profile else '未配置'}")
    effective_secret = store.get_secret(profile) if profile else env_secret
    print(f"Provider 凭据: {'可用' if effective_profile and effective_secret else '未检测到'}")
    print(f"Web 凭据: {'已配置' if runtime.web_ready() else '未配置'}")
    print(f"数据库: {db_url.split('@')[-1] if '@' in db_url else db_url}")
    print(f"前端构建: {'可用' if (frontend / 'index.html').exists() else '缺失'} ({frontend})")
    return 0


def cmd_providers(args: argparse.Namespace) -> int:
    store = ProviderProfileStore()
    if args.use:
        profile = store.set_active(args.use)
        secret = store.get_secret(profile)
        if profile.requires_api_key and not secret:
            raise CredentialStoreError(
                f"Provider {profile.profile_id} 的凭据不可用；请重新运行 onboard"
            )
        activate_profile(profile, secret)
        print(f"已切换活动 Provider：{profile.profile_id} ({profile.label} / {profile.model})")
        return 0
    data = store.load()
    active_id = data.get("active_profile", "")
    profiles = store.list_profiles()
    if not profiles:
        print("尚未保存 Provider 档案。运行 secagentx onboard。")
        return 0
    for profile in profiles:
        marker = "*" if profile.profile_id == active_id else " "
        print(f"{marker} {profile.profile_id}: {profile.label} / {profile.model} / {profile.api_base}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    checks: list[tuple[str, bool, str]] = []
    checks.append(("Python", sys.version_info >= (3, 10), sys.version.split()[0]))
    checks.append(("系统凭据库", CredentialStore.available(), "Keyring 或 Windows DPAPI"))
    try:
        profile = ProviderProfileStore().active()
        env_profile, env_secret = _environment_profile()
        profile = profile or env_profile
        checks.append(("Provider 配置", profile is not None, profile.label if profile else "运行 onboard"))
        if profile:
            secret = (
                ProviderProfileStore().get_secret(profile)
                if profile.profile_id != "environment" else env_secret
            )
            checks.append(("Provider 凭据", bool(secret), profile.env_key or "系统凭据库"))
    except ValueError as exc:
        profile = None
        checks.append(("Provider 配置", False, str(exc)))
    try:
        import yaml
        yaml.safe_load(config_path().read_text(encoding="utf-8"))
        checks.append(("业务配置", True, "config.yaml"))
    except Exception as exc:
        checks.append(("业务配置", False, str(exc)))
    checks.append(("Web 前端", (frontend_dist() / "index.html").exists(), str(frontend_dist())))
    try:
        from backend.storage.database import get_sqlite_path, _is_postgres
        db_detail = "PostgreSQL" if _is_postgres() else get_sqlite_path()
        checks.append(("数据库配置", True, str(db_detail)))
    except Exception as exc:
        checks.append(("数据库配置", False, str(exc)))

    if args.live and profile:
        try:
            secret = (
                ProviderProfileStore().get_secret(profile)
                if profile.profile_id != "environment" else env_secret
            )
            reply = asyncio.run(_verify_profile(profile, secret))
            checks.append(("模型实时请求", True, reply))
        except Exception as exc:
            checks.append(("模型实时请求", False, str(exc)))

    failed = False
    for name, ok, detail in checks:
        print(f"[{'OK' if ok else 'FAIL'}] {name}: {detail}")
        failed = failed or not ok
    return 1 if failed else 0


def cmd_ui(args: argparse.Namespace) -> int:
    source = frontend_dir()
    target = Path(args.path).expanduser().resolve()
    if args.ui_command == "init":
        if target.exists() and any(target.iterdir()):
            raise FileExistsError(f"目标目录非空，拒绝覆盖: {target}")
        shutil.copytree(
            source,
            target,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(
                "node_modules", "dist", ".vite", "coverage",
                ".npm-cache*", ".node-tmp*",
            ),
        )
        print(f"企业前端模板已生成: {target}")
        print(f"下一步: cd /d \"{target}\" && npm ci && npm run dev")
        return 0
    if not (target / "package.json").exists():
        raise FileNotFoundError(f"不是有效的 SecAgentX 前端目录: {target}")
    npm_executable = "npm.cmd" if os.name == "nt" else "npm"
    command = [npm_executable, "run", "dev" if args.ui_command == "dev" else "build"]
    return subprocess.call(command, cwd=target)


def _onboard_defaults() -> argparse.Namespace:
    return argparse.Namespace(
        provider="", profile="default", api_base="", model="", api_key_env="",
        timeout=60.0, non_interactive=False, accept_risk=False, skip_web=False,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secagentx", description="SecAgentX 企业安全智能体")
    parser.add_argument("--version", action="version", version=f"SecAgentX {_version()}")
    parser.add_argument("-q", "--query", help="兼容模式：执行一次查询")
    parser.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    parser.add_argument("--conv", "--conversation", dest="conversation_id", default="")
    sub = parser.add_subparsers(dest="command")

    onboard = sub.add_parser("onboard", aliases=["configure"], help="配置并验证模型 Provider")
    onboard.add_argument("--provider", choices=sorted(PROVIDER_PRESETS))
    onboard.add_argument("--profile", default="default")
    onboard.add_argument("--api-base", default="")
    onboard.add_argument("--model", default="")
    onboard.add_argument("--api-key-env", default="")
    onboard.add_argument("--timeout", type=float, default=60.0)
    onboard.add_argument("--non-interactive", action="store_true")
    onboard.add_argument("--accept-risk", action="store_true")
    onboard.add_argument("--skip-web", action="store_true")

    chat = sub.add_parser("chat", help="进入 CLI 多轮对话")
    chat.add_argument("-q", "--query", default="")
    chat.add_argument("--json", action="store_true")
    chat.add_argument("--conv", "--conversation", dest="conversation_id", default="")
    ask = sub.add_parser("ask", help="执行一次查询")
    ask.add_argument("query")
    ask.add_argument("--json", action="store_true")
    ask.add_argument("--conv", dest="conversation_id", default="")

    for name, help_text in (("dashboard", "启动并打开 Web 控制台"), ("serve", "只启动 API/WebSocket")):
        serve = sub.add_parser(name, help=help_text)
        serve.add_argument("--host", default="127.0.0.1")
        serve.add_argument("--port", type=int, default=8000)
        serve.add_argument(
            "--allow-remote", action="store_true",
            help="确认允许监听非回环地址（生产环境仍应配置 TLS/防火墙）",
        )
        serve.add_argument("--ui", default="", help="自定义前端 dist 目录")
        serve.add_argument("--no-open", action="store_true")
        serve.add_argument("--non-interactive", action="store_true")
        serve.add_argument("--log-level", default="info", choices=("critical", "error", "warning", "info", "debug"))

    sub.add_parser("status", help="显示当前运行配置")
    providers = sub.add_parser("providers", help="列出或切换 Provider 档案")
    providers.add_argument("--use", metavar="PROFILE_ID", default="")
    doctor = sub.add_parser("doctor", help="诊断环境、配置和端到端连接")
    doctor.add_argument("--live", action="store_true", help="执行真实模型请求")

    ui = sub.add_parser("ui", help="生成或构建企业自定义前端")
    ui_sub = ui.add_subparsers(dest="ui_command", required=True)
    for action in ("init", "dev", "build"):
        item = ui_sub.add_parser(action)
        item.add_argument("path")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.query and not args.command:
            return cmd_chat(args)
        if not args.command:
            if not ProviderProfileStore().active() and not _has_legacy_provider():
                return cmd_onboard(_onboard_defaults())
            args.query = ""
            return cmd_chat(args)
        if args.command in ("onboard", "configure"):
            return cmd_onboard(args)
        if args.command in ("chat", "ask"):
            return cmd_chat(args)
        if args.command == "dashboard":
            return _serve(args, open_browser=True)
        if args.command == "serve":
            return _serve(args, open_browser=False)
        if args.command == "status":
            return cmd_status(args)
        if args.command == "providers":
            return cmd_providers(args)
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "ui":
            return cmd_ui(args)
        parser.print_help()
        return 0
    except KeyboardInterrupt:
        print("\n已取消。")
        return 130
    except Exception as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
