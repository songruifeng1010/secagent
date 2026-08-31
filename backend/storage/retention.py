"""
数据保留策略 — 自动清理过期事件，防止 events 表无限增长。

配置项（config.yaml auto_operation.data_retention）:
  enabled: true
  event_retention_days: 90         # 事件保留天数
  conversation_retention_days: 30  # 对话记录保留天数
  ioc_retention_days: 365          # IOC 保留天数
  run_interval_hours: 24           # 清理周期
"""
import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("secagentx.retention")


class DataRetention:
    """数据保留策略执行器"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        retention_cfg = self.config.get("data_retention", {}) if self.config else {}
        self.enabled = retention_cfg.get("enabled", False)
        self._event_days = int(retention_cfg.get("event_retention_days", 90))
        self._conv_days = int(retention_cfg.get("conversation_retention_days", 30))
        self._ioc_days = int(retention_cfg.get("ioc_retention_days", 365))
        self._interval_hours = int(retention_cfg.get("run_interval_hours", 24))
        self._last_run: Optional[str] = None

    def get_summary(self) -> dict:
        return {
            "enabled": self.enabled,
            "event_retention_days": self._event_days,
            "conversation_retention_days": self._conv_days,
            "ioc_retention_days": self._ioc_days,
            "run_interval_hours": self._interval_hours,
            "last_run": self._last_run,
        }

    async def run_once(self) -> dict:
        """执行一次清理，返回清理统计"""
        if not self.enabled:
            return {"enabled": False, "reason": "数据保留策略未启用"}

        from backend.storage.database import Repository
        repo = Repository()
        stats = {}
        try:
            now = datetime.now(timezone.utc)

            # 1. 清理过期事件
            event_cutoff = (now - timedelta(days=self._event_days)).isoformat()
            result = await repo.execute(
                "DELETE FROM events WHERE created_at < ?",
                (event_cutoff,),
            )
            stats["events_deleted"] = repo._get_rowcount(result)

            # 2. 清理过期对话（及关联消息）
            conv_cutoff = (now - timedelta(days=self._conv_days)).isoformat()
            # 先删除消息
            msg_result = await repo.execute(
                "DELETE FROM messages WHERE conversation_id IN "
                "(SELECT id FROM conversations WHERE created_at < ?)",
                (conv_cutoff,),
            )
            stats["messages_deleted"] = repo._get_rowcount(msg_result)
            # 再删除对话
            conv_result = await repo.execute(
                "DELETE FROM conversations WHERE created_at < ?",
                (conv_cutoff,),
            )
            stats["conversations_deleted"] = repo._get_rowcount(conv_result)

            # 3. 清理过期 IOC
            ioc_cutoff = (now - timedelta(days=self._ioc_days)).isoformat()
            ioc_result = await repo.execute(
                "DELETE FROM ioc_database WHERE last_seen < ?",
                (ioc_cutoff,),
            )
            stats["ioc_deleted"] = repo._get_rowcount(ioc_result)

            # 4. 清理过期 agent_logs
            log_result = await repo.execute(
                "DELETE FROM agent_logs WHERE created_at < ?",
                (event_cutoff,),
            )
            stats["agent_logs_deleted"] = repo._get_rowcount(log_result)

            stats["status"] = "ok"
            self._last_run = now.isoformat()

            total = sum(v for k, v in stats.items() if isinstance(v, int))
            logger.info(
                "数据保留清理完成: %d 条事件, %d 条消息, %d 条对话, %d 条 IOC, %d 条日志 (共 %d 条)",
                stats.get("events_deleted", 0),
                stats.get("messages_deleted", 0),
                stats.get("conversations_deleted", 0),
                stats.get("ioc_deleted", 0),
                stats.get("agent_logs_deleted", 0),
                total,
            )

        except Exception as e:
            logger.error(f"数据保留清理失败: {e}")
            stats["status"] = "error"
            stats["error"] = str(e)
        finally:
            await repo.close()

        return stats


# 全局单例
data_retention = DataRetention()
