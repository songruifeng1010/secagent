"""
熔断器 — 防止连续误封导致安全事件
"""
import os
import json
import time
import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path

CIRCUIT_FILE = os.getenv("CIRCUIT_FILE", "data/.circuit_breaker.json")

# 阈值配置（从 ConfigLoader 读取，可通过环境变量覆盖）
from ..utils.config_loader import config as _app_config
MAX_CONSECUTIVE_FAILURES = _app_config.circuit_max_failures  # 连续 N 次误封禁 → 熔断
MAX_DAILY_BLOCKS = _app_config.circuit_max_daily             # 每日最多封禁 IP 数
CIRCUIT_RESET_MINUTES = _app_config.circuit_reset_minutes    # 自动半开等待分钟数


class CircuitBreaker:
    """
    熔断器状态机: CLOSED → OPEN → HALF_OPEN → CLOSED

    - CLOSED: 正常运行，允许封禁操作
    - OPEN: 熔断，所有自动封禁被阻止
    - HALF_OPEN: 半开状态，允许一次试探操作
    """

    STATE_CLOSED = "closed"
    STATE_OPEN = "open"
    STATE_HALF_OPEN = "half_open"

    def __init__(self):
        self._state = self.STATE_CLOSED
        self._failures = 0
        self._total_blocks_today = 0
        self._last_failure_time = 0.0
        self._last_reset_date = ""
        self._logger = logging.getLogger("secagentx.circuit")
        self._escalate_callback = None  # 可选: 自动恢复失败时的通知回调
        self._loop = None
        # 异步文件锁 — 防止并发写入
        self._file_lock = asyncio.Lock()
        self._load_state()

    def _get_loop(self):
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
        return self._loop

    def set_escalate_callback(self, callback):
        """
        设置自动恢复失败通知回调。
        callback 签名: async def callback(message: str)
        在 main.py 初始化的适合注入 AutoEscalation
        """
        self._escalate_callback = callback

    def _load_state(self):
        """同步版本 — 在 __init__ 中调用，仅加载一次"""
        if os.path.exists(CIRCUIT_FILE):
            try:
                with open(CIRCUIT_FILE, "r") as f:
                    data = json.load(f)
                self._state = data.get("state", self.STATE_CLOSED)
                self._failures = data.get("failures", 0)
                self._total_blocks_today = data.get("blocks_today", 0)
                self._last_failure_time = data.get("last_failure", 0.0)
                self._last_reset_date = data.get("reset_date", "")
            except (json.JSONDecodeError, FileNotFoundError):
                pass

    def _save_state(self):
        """同步写状态文件（同步方法使用）"""
        os.makedirs(os.path.dirname(CIRCUIT_FILE) or ".", exist_ok=True)
        with open(CIRCUIT_FILE, "w") as f:
            json.dump({
                "state": self._state,
                "failures": self._failures,
                "blocks_today": self._total_blocks_today,
                "last_failure": self._last_failure_time,
                "reset_date": self._last_reset_date,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }, f, indent=2)

    async def _save_state_async(self):
        """异步写状态文件 — 避免阻塞事件循环（异步方法使用）"""
        os.makedirs(os.path.dirname(CIRCUIT_FILE) or ".", exist_ok=True)
        data = {
            "state": self._state,
            "failures": self._failures,
            "blocks_today": self._total_blocks_today,
            "last_failure": self._last_failure_time,
            "reset_date": self._last_reset_date,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        tmp = CIRCUIT_FILE + ".tmp"
        async with self._file_lock:
            try:
                import aiofiles
                async with aiofiles.open(tmp, "w") as f:
                    await f.write(json.dumps(data, indent=2))
                os.replace(tmp, CIRCUIT_FILE)
            except ImportError:
                # 降级：同步写（极少调用，影响可控）
                with open(tmp, "w") as f:
                    json.dump(data, f, indent=2)
                os.replace(tmp, CIRCUIT_FILE)

    def _reset_daily_if_needed(self):
        """每日重置封禁计数"""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if self._last_reset_date != today:
            self._total_blocks_today = 0
            self._last_reset_date = today
            self._save_state()

    def check(self) -> bool:
        """检查是否允许继续封禁操作"""
        now = time.time()
        self._reset_daily_if_needed()

        # 检查是否超过每日限额
        if self._total_blocks_today >= MAX_DAILY_BLOCKS:
            self._logger.warning(
                f"每日封禁限额已满 ({self._total_blocks_today}/{MAX_DAILY_BLOCKS})"
            )
            return False

        # OPEN 状态检查是否到半开时间
        if self._state == self.STATE_OPEN:
            if now - self._last_failure_time > CIRCUIT_RESET_MINUTES * 60:
                self._state = self.STATE_HALF_OPEN
                self._save_state()
                self._logger.info("熔断器从 OPEN 进入 HALF_OPEN 状态")
                return True
            self._logger.warning(
                f"熔断器 OPEN，距自动恢复还有 "
                f"{int((CIRCUIT_RESET_MINUTES * 60 - (now - self._last_failure_time)) / 60)} 分钟"
            )
            return False

        return True

    async def record_failure(self):
        """记录一次封禁失败（误判）"""
        self._failures += 1
        self._last_failure_time = time.time()

        # 检测：如果在 HALF_OPEN 状态下再次失败 → 自动恢复失败
        was_half_open = self._state == self.STATE_HALF_OPEN

        if self._failures >= MAX_CONSECUTIVE_FAILURES:
            self._state = self.STATE_OPEN
            if was_half_open:
                msg = (
                    f" 熔断器自动恢复失败！"
                    f"连续 {self._failures} 次误封禁（含恢复尝试），"
                    f"自动封禁已暂停 {CIRCUIT_RESET_MINUTES} 分钟。"
                    f"需要人工介入: 检查封禁规则和威胁情报准确度"
                )
                self._logger.critical(msg)
                # 异步通知回调（如果有）
                if self._escalate_callback:
                    try:
                        import asyncio
                        asyncio.create_task(self._escalate_callback(msg))
                    except (RuntimeError, ValueError):
                        self._logger.warning("熔断器通知回调执行失败", exc_info=True)
            else:
                self._logger.critical(
                    f" 熔断器触发: 连续 {self._failures} 次误封禁，"
                    f"自动封禁已暂停 {CIRCUIT_RESET_MINUTES} 分钟"
                )
        else:
            self._logger.warning(
                f"封禁失败记录 ({self._failures}/{MAX_CONSECUTIVE_FAILURES})"
            )
        await self._save_state_async()

    def record_success(self):
        """记录一次成功封禁（人工确认后），重置失败计数"""
        self._failures = 0
        self._state = self.STATE_CLOSED
        self._save_state()

    def record_block(self):
        """记录一次封禁操作（计入每日限额）"""
        self._reset_daily_if_needed()
        self._total_blocks_today += 1
        self._save_state()

    def get_status(self) -> dict:
        """获取熔断器当前状态"""
        return {
            "state": self._state,
            "failures": self._failures,
            "blocks_today": self._total_blocks_today,
            "daily_limit": MAX_DAILY_BLOCKS,
            "failure_threshold": MAX_CONSECUTIVE_FAILURES,
            "auto_reset_seconds": CIRCUIT_RESET_MINUTES * 60,
            "is_blocked": self._state == self.STATE_OPEN,
        }


# 全局单例
circuit_breaker = CircuitBreaker()

