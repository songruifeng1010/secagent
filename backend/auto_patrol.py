"""
自动安全巡检器 (AutoPatrol)

职责:
  在无人干预的情况下，定期巡检安全状态并自动维持:

  1. 封禁续期巡检 (block_renewal):
     - 每 30 分钟检查所有活跃封禁
     - 对即将过期的 IP 重新查询威胁情报
     - 威胁仍在 → 自动续期封禁
     - 超过最大续期次数 → 升级人工

  2. 事件重新关联 (event_reopen):
     - 检查已闭环事件的关联告警
     - 24h 内出现新的关联告警 → 自动重新调查

  3. 健康检查报告 (health_report):
     - 定期输出系统运行状态摘要

使用方式:
    patrol = AutoPatrol(orchestrator, escalator, config)
    asyncio.create_task(patrol.start())
"""
import os
import json
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("secagentx.patrol")


class AutoPatrol:
    """
    自动安全巡检器

    使用示例:
        from backend.auto_patrol import AutoPatrol
        patrol = AutoPatrol(orchestrator, escalator, config)
        asyncio.create_task(patrol.start())
    """

    def __init__(self, orchestrator, escalator=None, config: dict = None):
        self.orchestrator = orchestrator
        self.escalator = escalator
        self.config = config or {}
        self._running = False
        self._patrol_count = 0
        self._renew_count: dict[str, int] = {}  # ip -> renew_count

        # 巡检配置
        patrol_cfg = self.config.get("patrol", {})
        self._interval = patrol_cfg.get("interval_seconds", 1800)
        self._renew_threshold = patrol_cfg.get("block_renew_threshold", 0.50)
        self._reopen_window = patrol_cfg.get("reopen_window_hours", 24)
        self._max_renew = patrol_cfg.get("max_renew_count", 3)

    async def start(self):
        """启动巡检循环"""
        if self._running:
            logger.warning("AutoPatrol 已在运行")
            return
        self._running = True

        logger.info(
            f"AutoPatrol 已启动: "
            f"间隔={self._interval}s, "
            f"续封阈值={self._renew_threshold}, "
            f"最大续封={self._max_renew}次"
        )

        # 首次巡检延迟 30 秒，避免与启动期数据库写入冲突
        await asyncio.sleep(30)

        while self._running:
            try:
                await self._patrol_cycle()
            except Exception as e:
                logger.error(f"巡检周期异常: {e}")

            self._patrol_count += 1
            await asyncio.sleep(self._interval)

    async def stop(self):
        """停止巡检"""
        self._running = False
        logger.info("AutoPatrol 已停止")

    async def patrol_once(self) -> dict:
        """执行一次巡检（供外部手动触发）"""
        result = await self._patrol_cycle()
        # 注意：不自增 _patrol_count，因为 _patrol_cycle() 调用后
        # 主循环中的调用者会负责自增（自增发生在 _patrol_cycle 返回之后）
        return result

    def get_stats(self) -> dict:
        """获取巡检统计"""
        return {
            "patrol_count": self._patrol_count,
            "interval_seconds": self._interval,
            "running": self._running,
            "renew_counts": dict(self._renew_count),
        }

    # ═══════════════════ 核心巡检逻辑 ═══════════════════

    async def _patrol_cycle(self) -> dict:
        """执行一轮完整巡检"""
        logger.info(f"  [巡检 #{self._patrol_count + 1}] 开始...")

        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "patrol_number": self._patrol_count + 1,
            "block_renewal": await self._patrol_block_list(),
            "event_reopen": await self._patrol_event_reopen(),
            "health": await self._health_check(),
        }

        # 数据清理（已闭环事件超过30天删除、旧日志清理）
        try:
            results["data_cleanup"] = await self._cleanup_old_data()
        except Exception as e:
            logger.warning(f"数据清理跳过（非致命）: {e}")
            results["data_cleanup"] = {"error": str(e), "skipped": True}

        # 输出巡检摘要
        block = results["block_renewal"]
        event = results["event_reopen"]
        logger.info(
            f"  [巡检 #{self._patrol_count + 1}] 完成: "
            f"封禁={block.get('active', 0)}条, "
            f"续封={block.get('renewed', 0)}条, "
            f"新调查={event.get('reopened', 0)}个, "
            f"异常={block.get('errors', 0) + event.get('errors', 0)}个"
        )

        return results

    # ═══════════════════ 巡检项 1: 封禁续期 ═══════════════════

    async def _patrol_block_list(self) -> dict:
        """巡检封禁列表：对即将过期的 IP 自动续期"""
        result = {
            "active": 0,
            "expiring": 0,
            "renewed": 0,
            "escalated": 0,
            "errors": 0,
            "details": [],
        }

        try:
            fw_response = await self.orchestrator.tools.execute(
                "firewall_manage", action="list"
            )
            if not fw_response.success:
                result["errors"] = 1
                result["error"] = fw_response.error
                return result

            rules = fw_response.data.get("rules", [])
            result["active"] = len(rules)

            now = datetime.now(timezone.utc)

            for rule in rules:
                ip = rule.get("ip", "")
                expire_str = rule.get("expire_at", "")
                if not ip or not expire_str:
                    continue

                try:
                    expire_time = datetime.fromisoformat(expire_str)
                except (ValueError, TypeError):
                    continue

                # 剩余时间
                remaining = (expire_time - now).total_seconds()
                duration = rule.get("duration_minutes", 120)
                remaining_ratio = remaining / (duration * 60) if duration > 0 else 0

                # 只在剩余时间 < 30% 时考虑续期
                if remaining_ratio > 0.3 and remaining > 300:
                    continue

                result["expiring"] += 1
                detail = {
                    "ip": ip,
                    "remaining_minutes": round(remaining / 60, 1),
                    "remaining_ratio": round(remaining_ratio, 2),
                    "renew_count": self._renew_count.get(ip, 0),
                }

                # 超过最大续期次数 → 升级人工
                if self._renew_count.get(ip, 0) >= self._max_renew:
                    detail["action"] = "escalated"
                    detail["reason"] = f"已达最大续期次数 ({self._max_renew})"
                    result["escalated"] += 1

                    if self.escalator:
                        await self.escalator.escalate(
                            incident_id=f"patrol-{ip}",
                            summary=f"IP {ip} 封禁已续期 {self._max_renew} 次，威胁可能持续存在",
                            confidence=0.5,
                            reason=f"自动续期达上限 {self._max_renew} 次，需人工判断",
                        )

                    result["details"].append(detail)
                    continue

                # 重新查询威胁情报
                try:
                    intel_result = await self.orchestrator.tools.execute(
                        "threat_intel",
                        indicator=ip,
                        indicator_type="ip",
                    )
                except Exception as e:
                    logger.warning(f"  威胁情报查询失败 {ip}: {e}")
                    detail["action"] = "query_failed"
                    detail["error"] = str(e)
                    result["errors"] += 1
                    result["details"].append(detail)
                    continue

                threat_score = 0
                if intel_result.success and intel_result.data:
                    threat_score = intel_result.data.get("score", 0) or \
                                   intel_result.data.get("malicious_count", 0) / 3.0

                # 威胁评分 ≥ 阈值 → 自动续期（先检查熔断器）
                if threat_score >= self._renew_threshold:
                    try:
                        from backend.security.circuit_breaker import circuit_breaker
                        if not circuit_breaker.check():
                            detail["action"] = "renew_skipped_cb"
                            detail["reason"] = "熔断器已触发，跳过续封"
                            result["details"].append(detail)
                            continue

                        renew_result = await self.orchestrator.tools.execute(
                            "firewall_manage",
                            action="block",
                            ip=ip,
                            reason=f"自动续期 (威胁评分 {threat_score:.0%})",
                            duration_minutes=120,
                            confidence=threat_score,
                        )

                        if renew_result.success:
                            self._renew_count[ip] = self._renew_count.get(ip, 0) + 1
                            result["renewed"] += 1
                            detail["action"] = "renewed"
                            detail["new_expire"] = renew_result.data.get("expire_at", "")
                            detail["threat_score"] = threat_score
                            logger.info(f"  [续封] {ip} (评分 {threat_score:.0%}, 续期 #{self._renew_count[ip]})")
                        else:
                            detail["action"] = "renew_failed"
                            detail["error"] = renew_result.error
                            result["errors"] += 1
                    except Exception as e:
                        detail["action"] = "renew_error"
                        detail["error"] = str(e)
                        result["errors"] += 1
                else:
                    detail["action"] = "skip"
                    detail["reason"] = f"威胁评分 {threat_score:.0%} < {self._renew_threshold:.0%}"
                    # 评分低 → 可能是误封，让封禁自然到期

                detail["threat_score"] = threat_score
                result["details"].append(detail)

        except Exception as e:
            logger.error(f"封禁巡检异常: {e}")
            result["errors"] += 1
            result["error"] = str(e)

        return result

    # ═══════════════════ 巡检项 2: 事件重新关联 ═══════════════════

    async def _patrol_event_reopen(self) -> dict:
        """巡检已闭环事件：是否有新的关联告警"""
        result = {
            "checked": 0,
            "reopened": 0,
            "errors": 0,
            "details": [],
        }

        from backend.storage.database import Repository
        db = None
        try:
            # 查询最近闭环的事件
            db = Repository()
            closed_events = await db.fetch_all(
                "SELECT id, title, source_ip, created_at FROM events "
                "WHERE status IN ('resolved', 'closed') "
                "ORDER BY created_at DESC LIMIT 20"
            )
            result["checked"] = len(closed_events)

            now = datetime.now(timezone.utc)
            reopen_window = timedelta(hours=self._reopen_window)

            for event in closed_events:
                # 检查闭环时间
                try:
                    closed_at = datetime.fromisoformat(event.get("created_at", ""))
                except (ValueError, TypeError):
                    continue

                # 确保 closed_at 是 timezone-aware
                if closed_at.tzinfo is None:
                    closed_at = closed_at.replace(tzinfo=timezone.utc)

                # 只检查在 reopen_window 内的闭环事件
                if now - closed_at > reopen_window:
                    continue

                # 查询最近是否有新的同类告警
                src_ip = event.get("source_ip", "")
                if not src_ip:
                    continue

                # 通过所有事件表查询是否有新的关联
                new_alerts = await db.fetch_all(
                    "SELECT id, title, created_at FROM events "
                    "WHERE source_ip = ? AND status = 'open' "
                    "AND created_at > ? "
                    "ORDER BY created_at DESC LIMIT 5",
                    (src_ip, event.get("created_at", "")),
                )

                if new_alerts:
                    # 有新的关联告警 → 自动重新调查
                    reopen_id = event["id"]
                    logger.info(f"   [重新调查] {reopen_id}: {src_ip} 有新告警")

                    # 触发重新分析
                    try:
                        async for _ in self.orchestrator.process_with_true_react(
                            f"重新调查事件 {reopen_id}，IP {src_ip} 出现新的关联告警"
                        ):
                            pass
                    except Exception as e:
                        logger.error(f"  重新调查失败: {e}")

                    result["reopened"] += 1
                    result["details"].append({
                        "event_id": reopen_id,
                        "src_ip": src_ip,
                        "new_alerts": len(new_alerts),
                        "action": "reopened",
                    })

        except Exception as e:
            logger.error(f"事件重新关联巡检异常: {e}")
            result["errors"] += 1
            result["error"] = str(e)
        finally:
            if db is not None:
                try:
                    await db.close()
                except Exception:
                    pass

        return result

    # ═══════════════════ 巡检项 3: 健康检查 ═══════════════════

    async def _health_check(self) -> dict:
        """系统运行状态检查"""
        result = {
            "status": "healthy",
            "agents": [],
            "tools": 0,
        }

        try:
            # Agent 状态
            agents = self.orchestrator.get_agent_statuses()
            result["agents"] = [
                {
                    "id": a.get("id", ""),
                    "name": a.get("name", ""),
                    "status": a.get("status", "unknown"),
                    "enabled": a.get("enabled", False),
                }
                for a in agents
            ]
            result["tools"] = self.orchestrator.tools.count()

            # 检查是否有 Agent 异常
            for agent in agents:
                if agent.get("status") == "error":
                    result["status"] = "degraded"

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result

    # ═══════════════════ 巡检项 4: 数据清理 ═══════════════════

    async def _cleanup_old_data(self) -> dict:
        """使用 DataRetention 模块执行数据清理，支持可配置的保留策略。"""
        from backend.storage.retention import DataRetention
        retention = DataRetention(self.config)
        # 如果 config 中没有显式启用，但 patrol 有数据保留配置，则启用
        if not retention.enabled:
            # 降级：使用传统清理（向后兼容）
            result = {
                "events_anonymized": 0,
                "audit_logs_deleted": 0,
                "errors": 0,
            }
            from backend.storage.database import Repository
            db = None
            try:
                now = datetime.now(timezone.utc)
                cutoff_30d = (now - timedelta(days=30)).isoformat()
                db = Repository()
                old_events = await db.fetch_all(
                    "SELECT id FROM events WHERE status IN ('resolved', 'closed') AND created_at < ?",
                    (cutoff_30d,),
                )
                for ev in old_events:
                    eid = ev["id"]
                    await db.execute(
                        "UPDATE events SET description='[已过期，内容已清理]', raw_data='{}' WHERE id=?",
                        (eid,),
                    )
                    result["events_anonymized"] += 1
                await db.execute(
                    "DELETE FROM agent_logs WHERE created_at < ?", (cutoff_30d,)
                )
                result["audit_logs_deleted"] = len(old_events)
            except Exception as e:
                logger.error(f"数据清理异常: {e}")
                result["errors"] += 1
            finally:
                if db is not None:
                    try:
                        await db.close()
                    except Exception:
                        pass
            return result

        return await retention.run_once()
