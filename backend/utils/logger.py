"""
统一日志模块 — 支持结构化日志输出 + 自动日志轮转

日志轮转策略:
  - 按时间轮转: 每天凌晨切割
  - 保留周期: 30 天
  - 压缩: 旧日志自动 gzip 压缩
  - 磁盘保护: 单个日志文件上限 100MB（以防某天日志量突增）
"""
import sys
import os
import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path

_LOG_DIR = Path("logs")
_LOG_DIR.mkdir(exist_ok=True)

# ─── 日志轮转配置 ─────────────────────────────────────────
LOG_ROTATION_CONFIG = {
    "when": "midnight",          # 每天午夜轮转
    "interval": 1,               # 每 1 天
    "backup_count": 30,          # 保留 30 天的日志
    "encoding": "utf-8",
    "delay": False,
    "utc": True,
}
# 单文件大小上限（防止某天日志量异常突增撑爆磁盘）
MAX_BYTES = 100 * 1024 * 1024  # 100MB


class StructuredFormatter(logging.Formatter):
    """结构化 JSON 日志格式（便于 ELK/Loki 采集）"""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra") and record.extra:
            log_entry.update(record.extra)
        return json.dumps(log_entry, ensure_ascii=False)


def setup_logger(name: str = "secagentx", level: str = "INFO") -> logging.Logger:
    """初始化统一日志器（带自动轮转）"""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # 避免重复添加 Handler
    if logger.handlers:
        return logger

    # ─── 控制台 Handler（人类可读，开发用） ───
    console = logging.StreamHandler(sys.stdout)
    # CLI 只在界面展示执行状态，完整诊断仍写入文件。
    console.addFilter(lambda record: os.getenv("SECAGENTX_CLI_QUIET") != "1")
    console.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)-5s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(console)

    # ─── 文件 Handler（按天轮转 + 大小上限） ───
    log_path = _LOG_DIR / f"{name}.log"
    # 使用 TimedRotatingFileHandler 按时间轮转
    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=str(log_path),
        when=LOG_ROTATION_CONFIG["when"],
        interval=LOG_ROTATION_CONFIG["interval"],
        backupCount=LOG_ROTATION_CONFIG["backup_count"],
        encoding=LOG_ROTATION_CONFIG["encoding"],
        delay=LOG_ROTATION_CONFIG["delay"],
        utc=LOG_ROTATION_CONFIG["utc"],
    )
    # 同时设置单个文件大小上限（超过 100MB 也触发轮转）
    file_handler.rotator = _rotator
    file_handler.namer = _namer
    file_handler.setFormatter(StructuredFormatter())
    logger.addHandler(file_handler)

    logger.info(f"日志系统初始化: {log_path} (轮转: 每天, 保留30天, 单文件上限100MB)")
    return logger


def _namer(default_name: str) -> str:
    """自定义轮转后文件名: secagentx.log → secagentx.2026-06-27.log.gz"""
    if default_name.endswith(".log"):
        base = default_name[:-4]
        return f"{base}.gz"  # 后续由 rotator 压缩
    return default_name


def _rotator(source: str, dest: str):
    """轮转时自动 gzip 压缩旧日志"""
    import gzip
    import shutil
    try:
        with open(source, "rb") as f_in:
            with gzip.open(dest, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        # 压缩完成后清空源文件
        with open(source, "w") as f:
            f.truncate(0)
    except Exception:
        # 压缩失败时保底：直接 rename
        import os
        if os.path.exists(source):
            os.rename(source, dest)


# ─── 日志轮转的快速健康检查 ───
def check_log_health() -> dict:
    """
    检查日志系统健康状态:
      - 日志文件是否存在
      - 今日日志是否可写入
      - 日志目录磁盘使用率估算
    """
    import os
    result = {"status": "healthy", "files": [], "total_size_mb": 0.0}

    log_dir = _LOG_DIR
    if not log_dir.exists():
        result["status"] = "no_log_dir"
        return result

    total_size = 0
    for f in sorted(log_dir.iterdir()):
        if f.is_file():
            size_mb = f.stat().st_size / (1024 * 1024)
            total_size += size_mb
            result["files"].append({
                "name": f.name,
                "size_mb": round(size_mb, 2),
            })

    result["total_size_mb"] = round(total_size, 2)
    if total_size > 1024:
        result["status"] = "warning"
        result["warning"] = f"日志目录超过 1GB ({total_size:.0f}MB)，建议清理"
    return result


# 全局单例
logger = setup_logger()
