"""定位源码检出与已安装 wheel 中的只读运行资源。"""

from __future__ import annotations

import os
from pathlib import Path


_BACKEND_DIR = Path(__file__).resolve().parent
_SOURCE_ROOT = _BACKEND_DIR.parent
_PACKAGED_ROOT = _BACKEND_DIR / "_assets"


def is_source_checkout() -> bool:
    return (_SOURCE_ROOT / "config.yaml").is_file() and (_SOURCE_ROOT / "frontend").is_dir()


def resource_root() -> Path:
    """返回只读资源根目录；发布 wheel 的资源位于 backend/_assets。"""
    override = os.getenv("SECAGENTX_RESOURCE_ROOT", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return _SOURCE_ROOT if is_source_checkout() else _PACKAGED_ROOT


def config_path() -> Path:
    override = os.getenv("SECAGENTX_CONFIG", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    local = Path.cwd() / "config.yaml"
    return local if local.is_file() else resource_root() / "config.yaml"


def knowledge_dir() -> Path:
    override = os.getenv("KNOWLEDGE_BASE_DIR", "").strip()
    return Path(override).expanduser().resolve() if override else resource_root() / "knowledge_data"


def frontend_dir() -> Path:
    return resource_root() / "frontend"


def frontend_dist() -> Path:
    override = os.getenv("SECAGENTX_FRONTEND_DIST", "").strip()
    return Path(override).expanduser().resolve() if override else frontend_dir() / "dist"
