"""
统一环境变量加载器 — 项目内所有模块统一调用，避免多次加载覆盖问题。

核心原则:
  1. 整个进程只加载 .env 一次
  2. os.environ.setdefault() 确保环境变量优先于 .env
  3. 提供统一入口 ensure_env_loaded()
"""
import os
import logging
from pathlib import Path

logger = logging.getLogger("secagentx.env")

_LOADED = False

from backend.runtime_assets import config_path, is_source_checkout, knowledge_dir, resource_root


def ensure_env_loaded(force_reload: bool = False) -> None:
    """确保 .env 文件仅被加载一次（幂等）。

    Args:
        force_reload: 强制重新加载（仅测试用，生产不要用）
    """
    global _LOADED
    if _LOADED and not force_reload:
        return

    dotenv_path = (resource_root() if is_source_checkout() else Path.cwd()) / ".env"
    if dotenv_path.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(str(dotenv_path), override=False)  # override=False 确保已有环境变量优先
            _LOADED = True
            logger.debug(f"Loaded .env from {dotenv_path}")
        except ImportError:
            logger.warning("python-dotenv not installed, skipping .env loading")
    else:
        logger.debug(f"No .env file found at {dotenv_path}")


def get_project_root() -> Path:
    """返回项目根目录的 Path 对象。"""
    return resource_root()


def init_environment() -> None:
    """初始化运行环境: 加载 .env + 设置 KNOWLEDGE_BASE_DIR。

    所有入口点 (main.py / api_server.py / cli.py) 调用此函数
    替代各自分散的初始化逻辑。
    """
    ensure_env_loaded()
    try:
        from backend.config.runtime_settings import activate_runtime_settings
        activate_runtime_settings()
    except Exception as exc:
        logger.warning("安全运行配置加载失败，将使用环境变量: %s", exc)
    # onboarding 保存的活动 Provider 优先于项目默认配置，但不覆盖进程显式传入的
    # SECAGENTX_ACTIVE_PROVIDER，保证 CLI/Web/Agent 使用同一模型路由。
    if not os.getenv("SECAGENTX_ACTIVE_PROVIDER"):
        try:
            from backend.config.provider_profiles import activate_stored_profile
            activate_stored_profile()
        except Exception as exc:
            logger.warning("Provider 档案加载失败，将使用环境变量/默认配置: %s", exc)
    os.environ.setdefault(
        "KNOWLEDGE_BASE_DIR",
        str(knowledge_dir()),
    )
    os.environ.setdefault("SECAGENTX_CONFIG", str(config_path()))
    # 源码运行保持历史行为；wheel 安装后不得切换到只读 site-packages。
    if is_source_checkout():
        os.chdir(str(resource_root()))
