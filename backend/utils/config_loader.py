"""
ConfigLoader — 统一配置加载器

职责:
  1. 从 config.yaml 加载配置
  2. 递归替换 ${ENV_VAR} 占位符为环境变量值
  3. 提供点号分隔的 get() 方法安全取值
  4. 单例模式，全局只加载一次

使用方式:
    from backend.utils.config_loader import ConfigLoader

    cfg = ConfigLoader()
    block_threshold = cfg.get("auto_operation.thresholds.auto_block", 0.70)
    db_path = cfg.get("storage.database.path", "data/secagentx.db")
    api_key = cfg.get("llm.deepseek.api_key", "")  # 自动解析 ${DEEPSEEK_API_KEY}
"""

import os
import re
import yaml
from pathlib import Path
from typing import Any, Optional


_ENV_VAR_PATTERN = re.compile(r'\$\{(\w+)\}')


class ConfigLoader:
    """统一配置加载器（单例）"""

    _instance: Optional['ConfigLoader'] = None
    _config: dict = {}
    _loaded: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, path: Optional[str] = None, auto_load: bool = True):
        if self._loaded:
            return
        if auto_load:
            self.load(path)

    def load(self, path: Optional[str] = None) -> dict:
        """
        加载配置文件。

        Args:
            path: 配置文件路径，默认取环境变量 SECAGENTX_CONFIG 或 "config.yaml"

        Returns:
            完整配置字典
        """
        if self._loaded:
            return self._config

        if path is None:
            path = os.getenv("SECAGENTX_CONFIG", "config.yaml")

        p = Path(path)
        if not p.exists():
            self._config = {}
            self._loaded = True
            return self._config

        with open(p, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        self._config = self._resolve_env(raw)
        self._loaded = True
        return self._config

    def get(self, key: str, default: Any = None) -> Any:
        """
        点号分隔取值。

        示例:
            cfg.get("auto_operation.enabled", False)
            cfg.get("llm.deepseek.api_key", "")
            cfg.get("federation.region_id", "default")
        """
        if not self._config:
            return default

        keys = key.split(".")
        val = self._config
        for k in keys:
            if not isinstance(val, dict):
                return default
            val = val.get(k)
            if val is None:
                return default
        return val

    def all(self) -> dict:
        """返回完整配置字典"""
        return dict(self._config)

    def reload(self, path: Optional[str] = None) -> dict:
        """重新加载配置"""
        self._loaded = False
        self.load(path)

    @staticmethod
    def _resolve_env(node: Any) -> Any:
        """递归替换字符串中的 ``${VAR}`` 为环境变量值。

        未配置的变量解析为空字符串，避免把占位符字面量误当成 API Key、
        密码或 URL 发送给外部服务。
        """
        if isinstance(node, str):
            def _replacer(m: re.Match) -> str:
                return os.getenv(m.group(1), "")
            return _ENV_VAR_PATTERN.sub(_replacer, node)
        elif isinstance(node, dict):
            return {k: ConfigLoader._resolve_env(v) for k, v in node.items()}
        elif isinstance(node, list):
            return [ConfigLoader._resolve_env(item) for item in node]
        return node

    # ─── 便捷属性 ───

    @property
    def debug(self) -> bool:
        return self.get("general.debug", False)

    @property
    def database_url(self) -> str:
        return os.getenv("DATABASE_URL") or self.get("storage.database.url", "sqlite:///data/secagentx.db")

    @property
    def firewall_backend(self) -> str:
        return os.getenv("FIREWALL_BACKEND") or self.get("tools.firewall.backend", "disabled")

    @property
    def auto_operation_enabled(self) -> bool:
        return self.get("auto_operation.enabled", False)

    @property
    def patrol_interval(self) -> int:
        return self.get("auto_operation.patrol.interval_seconds", 1800)

    @property
    def block_threshold(self) -> float:
        return self.get("auto_operation.thresholds.auto_block", 0.70)

    @property
    def circuit_max_failures(self) -> int:
        return self.get("circuit_breaker.max_consecutive_failures", 3)

    @property
    def circuit_max_daily(self) -> int:
        return self.get("circuit_breaker.max_daily_blocks", 20)

    @property
    def circuit_reset_minutes(self) -> int:
        return self.get("circuit_breaker.reset_minutes", 30)


# 全局默认实例
config = ConfigLoader()
