"""
自动告警接入器 (AutoIngestor)

职责:
  让 SecAgentX 从"等人来问"变成"主动接警"。
  自动从 Webhook / Kafka / Syslog 等源接收告警，
  送入 Orchestrator 分析，并根据置信度自动决策。

工作流:
  告警源 → AutoIngestor._handle_alert()
            │
            ▼
        Orchestrator.process_user_input()
            │
            ▼
        获取置信度
            │
      ┌─────┴──────────┐
      │                 │
    ≥0.85           0.70~0.85         <0.30
      │                 │                 │
      ▼                 ▼                 ▼
  自动闭环        自动封禁           自动升级通知
  + 写入DB      + EffectObserver    (AutoEscalation)

使用方式:
    ingestor = AutoIngestor(orchestrator, escalator, config)
    await ingestor.start()  # 启动所有消费者（Webhook/Kafka/Syslog）
"""
import os
import re
import json
import time
import uuid
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Callable

logger = logging.getLogger("secagentx.ingestor")


class AutoIngestor:
    """
    自动告警接入器

    支持的数据源:
    1. Webhook 回调（由 api_server.py 调用 ingestor.handle_webhook()）
    2. Kafka 消费者（异步监听，可选）
    3. Syslog 监听（UDP，可选）

    告警去重:
      基于 (src_ip, title/type) 组合在 dedup_window_seconds 窗口内去重。
      配置文件: auto_operation.dedup.window_seconds (默认 1800s=30分钟)

    使用示例:
        from backend.auto_ingestor import AutoIngestor
        ingestor = AutoIngestor(orchestrator, escalator, config)
        asyncio.create_task(ingestor.start())

        # 在 FastAPI 路由中:
        @app.post("/webhook/alert")
        async def webhook_alert(data: dict):
            result = await ingestor.handle_webhook(data)
            return result
    """

    def __init__(self, orchestrator, escalator=None, config: dict = None):
        self.orchestrator = orchestrator
        self.escalator = escalator
        self.config = config or {}
        self._queue: asyncio.Queue = asyncio.Queue(
            maxsize=self._get_cfg("ingestion.max_queue_size", 1000)
        )
        self._processed_count = 0
        self._last_stats_time = time.time()
        self._running = False
        self._consumer_tasks: list[asyncio.Task] = []

        # 阈值配置
        self.thresholds = self.config.get("thresholds", {})
        self._auto_close_threshold = self.thresholds.get("auto_close", 0.85)
        self._auto_block_threshold = self.thresholds.get("auto_block", 0.70)
        self._manual_threshold = self.thresholds.get("manual_escalation", 0.30)

        # ─── 告警去重 ───
        dedup_cfg = config.get("dedup", {}) if config else {}
        self._dedup_window = float(dedup_cfg.get("window_seconds", 1800))  # 默认 30 分钟
        self._dedup_max_entries = int(dedup_cfg.get("max_entries", 10000))  # 最大追踪数
        # 格式: {dedup_key: timestamp_of_first_seen}
        self._seen_alerts: dict[str, float] = {}
        self._last_dedup_cleanup = time.time()

    def _get_cfg(self, key: str, default=None):
        """按点分路径获取配置值"""
        parts = key.split(".")
        val = self.config
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p, {})
            else:
                return default
        return val if val != {} else default

    # ═══════════════════ 告警去重 ═══════════════════

    def _dedup_key(self, alert: dict) -> str:
        """生成去重键: (src_ip, alert_type) 组合。

        对于无源 IP 的告警使用 title 做去重键。
        """
        src_ip = (alert.get("src_ip") or alert.get("source_ip") or "").strip()
        alert_type = (alert.get("type") or alert.get("alert_type") or alert.get("title") or "unknown").strip()
        if src_ip:
            return f"{src_ip}::{alert_type}"
        return f"noip::{alert_type}"

    def _is_duplicate(self, alert: dict) -> bool:
        """检查告警是否在去重窗口内的重复告警。

        幂等设计: 同一 alert_id 出现也视为重复（避免同一告警多路入队）。
        """
        now = time.time()

        # 1. 定期清理过期记录，防止内存泄漏
        if now - self._last_dedup_cleanup > 300:  # 每 5 分钟清理一次
            self._dedup_cleanup(now)

        # 2. 如果已有相同 alert_id，直接视为重复
        alert_id = alert.get("id", "")
        if alert_id and alert_id in self._seen_alerts:
            return True

        # 3. 按 (src_ip, type) 组合去重
        key = self._dedup_key(alert)
        if key in self._seen_alerts:
            elapsed = now - self._seen_alerts[key]
            if elapsed < self._dedup_window:
                logger.debug(
                    "去重跳过: key=%s, 距上次 %.0fs (窗口 %ds)",
                    key, elapsed, self._dedup_window,
                )
                return True

        # 记录新告警
        self._seen_alerts[key] = now
        if alert_id:
            self._seen_alerts[alert_id] = now

        # 限制追踪数量，超过时淘汰最早的 1/3
        if len(self._seen_alerts) > self._dedup_max_entries:
            self._dedup_shrink()

        return False

    def _dedup_cleanup(self, now: float) -> None:
        """清理超过去重窗口的过期记录。"""
        cutoff = now - self._dedup_window
        old_count = len(self._seen_alerts)
        self._seen_alerts = {k: v for k, v in self._seen_alerts.items() if v >= cutoff}
        self._last_dedup_cleanup = now
        removed = old_count - len(self._seen_alerts)
        if removed > 0:
            logger.debug("去重表清理: 移除 %d 条过期记录, 当前 %d 条", removed, len(self._seen_alerts))

    def _dedup_shrink(self) -> None:
        """超过最大追踪数时淘汰最早的 1/3。"""
        sorted_items = sorted(self._seen_alerts.items(), key=lambda x: x[1])
        remove_count = len(sorted_items) // 3
        self._seen_alerts = dict(sorted_items[remove_count:])
        logger.info(
            "去重表收缩: 移除 %d 条, 当前 %d 条",
            remove_count, len(self._seen_alerts),
        )

    def get_dedup_stats(self) -> dict:
        """返回去重模块状态（调试/监控用）"""
        return {
            "window_seconds": self._dedup_window,
            "tracked_entries": len(self._seen_alerts),
        }

    # ═══════════════════ 公开接口 ═══════════════════

    async def start(self):
        """启动所有消费者（非阻塞）"""
        if self._running:
            logger.warning("AutoIngestor 已在运行")
            return
        self._running = True

        # 启动队列消费者（核心处理循环）
        self._consumer_tasks.append(
            asyncio.create_task(self._process_queue(), name="ingestor-queue")
        )

        # 更新队列大小 Prometheus 指标
        try:
            from backend.monitoring.metrics import set_queue_size
            set_queue_size(self._queue.qsize())
        except ImportError:
            logger.debug("Prometheus metrics 模块未安装，跳过指标更新")

        # 启动 Kafka 消费者（如配置）
        kafka_topic = self._get_cfg("ingestion.kafka_topic", "")
        kafka_bootstrap = self._get_cfg("ingestion.kafka_bootstrap", "")
        if kafka_topic and kafka_bootstrap:
            self._consumer_tasks.append(
                asyncio.create_task(
                    self._consume_kafka(kafka_topic, kafka_bootstrap),
                    name="ingestor-kafka"
                )
            )

        # 启动 Syslog 监听（如配置）
        syslog_port = self._get_cfg("ingestion.syslog_port", 0)
        if syslog_port:
            self._consumer_tasks.append(
                asyncio.create_task(
                    self._listen_syslog(syslog_port),
                    name="ingestor-syslog"
                )
            )

        logger.info(
            f"AutoIngestor 已启动: "
            f"队列上限={self._queue.maxsize}, "
            f"消费者={len(self._consumer_tasks)}"
        )

    async def stop(self):
        """停止所有消费者"""
        self._running = False
        for task in self._consumer_tasks:
            task.cancel()
        await asyncio.gather(*self._consumer_tasks, return_exceptions=True)
        self._consumer_tasks.clear()
        logger.info("AutoIngestor 已停止")

    async def handle_webhook(self, alert_data: dict) -> dict:
        """
        Webhook 入口（由 FastAPI 路由调用）

        参数:
            alert_data: 告警数据（需包含 title / description / src_ip 等字段）

        返回:
            处理结果
        """
        if not self._running:
            await self.start()

        # 标准化告警格式
        alert = self._normalize_alert(alert_data)
        logger.info(f"收到 Webhook 告警: {alert.get('id', '?')} - {alert.get('title', '?')}")

        # 告警去重检查（同一 src_ip + type 在窗口内只处理一次）
        if self._is_duplicate(alert):
            logger.info(
                "去重跳过重复告警: id=%s, src_ip=%s, type=%s",
                alert.get("id", "?"),
                alert.get("src_ip", "?"),
                alert.get("type", "?"),
            )
            return {
                "status": "duplicated",
                "alert_id": alert["id"],
                "queue_size": self._queue.qsize(),
                "message": "重复告警已跳过（去重窗口内已处理过同类告警）",
                "dedup_window_seconds": self._dedup_window,
            }

        # 入队等待处理
        try:
            await self._queue.put(alert)
            return {
                "status": "queued",
                "alert_id": alert["id"],
                "queue_size": self._queue.qsize(),
                "message": "告警已入队等待分析",
            }
        except asyncio.QueueFull:
            logger.warning(f"告警队列已满，丢弃告警: {alert.get('id', '?')}")
            return {
                "status": "dropped",
                "alert_id": alert.get("id", ""),
                "message": "告警队列已满，请稍后重试",
            }

    async def handle_alert_direct(self, alert: dict) -> dict:
        """
        直接处理告警（不走队列，供内部/测试使用）

        返回:
            {"status": str, "action": str, "confidence": float, ...}
        """
        if self._is_duplicate(alert):
            logger.info(
                "去重跳过重复告警(直接处理): src_ip=%s, type=%s",
                alert.get("src_ip", "?"), alert.get("type", "?"),
            )
            return {
                "status": "duplicated",
                "alert_id": alert.get("id", "?"),
                "message": "重复告警已跳过",
            }
        return await self._process_alert(alert)

    def get_stats(self) -> dict:
        """获取处理统计"""
        return {
            "processed_count": self._processed_count,
            "queue_size": self._queue.qsize(),
            "running": self._running,
            "dedup": self.get_dedup_stats(),
        }

    # ═══════════════════ 统一入队（带去重） ═══════════════════

    async def _enqueue(self, alert: dict) -> bool:
        """统一入队: 去重检查 → 入队。所有消费者数据源统一走此入口。

        Returns:
            True 表示入队成功, False 表示去重跳过或队列满
        """
        if self._is_duplicate(alert):
            logger.debug(
                "去重跳过: src_ip=%s, type=%s",
                alert.get("src_ip", "?"), alert.get("type", "?"),
            )
            return False

        try:
            await self._queue.put(alert)
            return True
        except asyncio.QueueFull:
            logger.warning("队列已满，丢弃告警: %s", alert.get("id", "?"))
            return False

    # ═══════════════════ 核心处理 ═══════════════════

    @staticmethod
    def _extract_confidence_from_text(text: str) -> Optional[float]:
        """
        从 LLM 回复文本中解析结构化裁决的置信度。

        注意: AutoIngestor 不应直接解析 LLM 文本中的置信度。
        正确做法是在 Agent 输出层就提取 structured 字段。

        这里只做两层兜底:
          1. 优先解析 ```verdict\n{...}\n``` JSON 块中的 confidence 字段
          2. 如果连 JSON 块都没有，返回 None 而不是用正则去"猜"
             （让调用方使用默认值或人工复核）
        """
        if not text:
            return None

        # 【唯一安全方式】解析 structured verdict JSON 块
        match = re.search(r'```verdict\s*\n(.*?)\n```', text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(1).strip())
                conf = parsed.get("confidence")
                if isinstance(conf, (int, float)) and 0.0 <= conf <= 1.0:
                    return float(conf)
            except (json.JSONDecodeError, ValueError):
                pass

        # 如果 LLM 没有输出结构化 JSON 块，不依赖正则去"猜"置信度
        # 返回 None 触发调用方的默认处理逻辑（保守策略）
        return None

    async def _rule_based_fallback(self, src_ip: str, title: str,
                                   alert_type: str = "", severity: str = "") -> Optional[float]:
        """
        规则引擎兜底评估置信度（LLM 结构化裁决解析失败时使用）

        两层兜底（从可信到一般）:
          1. 本地 IOC 威胁情报库查询（离线、真实）:
              命中恶意 IP → 返回情报置信度（≥0.70，可触发自动封禁）
          2. 告警特征规则评估（无 IOC 命中时）:
              高危特征(暴力破解/C2/勒索等) → 0.55
              中危特征(扫描/探测等) → 0.42
              按严重度加权 0.45-0.50

        返回 None 表示连规则评估也无法给出合理置信度（保持原保守策略）。
        """
        # ─── 第 1 层: 本地 IOC 威胁情报库 ───
        if src_ip:
            try:
                from backend.storage.database import Repository, _is_postgres
                db = Repository()
                if _is_postgres():
                    row = await db.fetch_one(
                        "SELECT confidence FROM ioc_database "
                        "WHERE ioc_type='ip' AND ioc_value=$1 LIMIT 1",
                        (src_ip,),
                    )
                else:
                    row = await db.fetch_one(
                        "SELECT confidence FROM ioc_database "
                        "WHERE ioc_type='ip' AND ioc_value=? LIMIT 1",
                        (src_ip,),
                    )
                await db.close()
                if row and row.get("confidence") is not None:
                    conf = float(row["confidence"])
                    logger.info(f"规则兜底: IOC 库命中 {src_ip} (情报置信度={conf:.2f})")
                    return max(0.70, conf)
            except Exception as e:
                logger.warning(f"规则兜底 IOC 查询失败: {e}")

        # ─── 第 2 层: 告警特征规则 ───
        # 基础分 0.25（低于 manual_escalation 阈值 0.30）：
        # 无任何风险特征的告警应保守升级人工，而非停留在 monitoring。
        score = 0.25
        combined = f"{title} {alert_type}".lower()

        high_risk_kw = [
            "暴力破解", "bruteforce", "brute-force", "c2", "命令控制",
            "勒索", "ransomware", "钓鱼", "phishing", "挖矿", "mining",
            "webshell", "后门", "backdoor", "入侵", "intrusion",
            "恶意", "malware", "横向", "lateral", "提权", "privilege escalation",
        ]
        medium_risk_kw = [
            "扫描", "scan", "探测", "probe", "弱口令", "weak password",
            "撞库", "credential stuffing", "爆破", "登录尝试", "login attempt",
        ]

        for kw in high_risk_kw:
            if kw in combined:
                score = max(score, 0.55)
                break
        for kw in medium_risk_kw:
            if kw in combined:
                score = max(score, 0.42)
                break

        # 严重度加权
        sev = (severity or "").lower()
        if "紧急" in sev or "critical" in sev:
            score = max(score, 0.50)
        elif "高危" in sev or "high" in sev:
            score = max(score, 0.45)

        logger.info(f"规则兜底: 特征评估 score={score:.2f} (src_ip={src_ip or '无'})")
        return score

    async def _process_queue(self):
        """队列消费者：持续从队列中取出告警并处理"""
        while self._running:
            try:
                alert = await self._queue.get()
                try:
                    result = await self._process_alert(alert)
                    logger.info(
                        f"告警处理完成: {alert.get('id', '?')} "
                        f"→ action={result.get('action', '?')} "
                        f"confidence={result.get('confidence', 0):.0%}"
                    )
                except Exception as e:
                    logger.error(f"告警处理异常: {alert.get('id', '?')}: {e}")
                finally:
                    self._queue.task_done()
                    self._processed_count += 1
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"队列消费者异常: {e}")
                await asyncio.sleep(1)

    async def _process_alert(self, alert: dict) -> dict:
        """
        处理单条告警的核心逻辑

        流程:
        1. 构建分析问句 → 送入 Orchestrator
        2. 获取分析结果和置信度
        3. 按置信度分层决策
        """
        # Prometheus 指标
        try:
            from backend.monitoring.metrics import record_alert as _record_alert
        except ImportError:
            # metrics 模块未安装时使用空函数
            def _record_alert(action="unknown"): pass

        alert_id = alert.get("id", f"auto-{uuid.uuid4().hex[:8]}")
        title = alert.get("title", "未知告警")
        src_ip = alert.get("src_ip", "") or alert.get("source_ip", "")
        description = alert.get("description", "") or alert.get("message", "")

        # Step 1: 构建分析输入
        query_parts = [f"分析告警: {title}"]
        if description:
            query_parts.append(f"描述: {description}")
        if src_ip:
            query_parts.append(f"源IP: {src_ip}")
        query = "\n".join(query_parts)

        # Step 2: 送入 Orchestrator 分析（使用统一 TrueReAct 入口）
        final_result = {"summary": "", "confidence": None}
        try:
            async for chunk in self.orchestrator.process(query):
                chunk_type = chunk.get("type", "")
                if chunk_type == "true_react_complete":
                    content = chunk.get("content", "") or chunk.get("summary", "")
                    final_result["summary"] = content
                    # 从 LLM 回复文本中解析结构化裁决里的置信度
                    confidence = self._extract_confidence_from_text(content)
                    if confidence is not None:
                        final_result["confidence"] = confidence
                    else:
                        # 结构化解析失败 → 使用保守默认值
                        logger.warning(
                            f"置信度结构化解析失败: alert_id={alert_id}, "
                            f"LLM 未输出标准裁决 JSON，将使用保守策略"
                        )
        except Exception as e:
            logger.error(f"Orchestrator 分析失败: {e}")
            return {
                "alert_id": alert_id,
                "status": "error",
                "action": "error",
                "error": str(e),
            }

        confidence = final_result.get("confidence", None)

        # 规则引擎兜底：LLM 未输出结构化置信度时，用 IOC 情报库 + 特征规则评估，
        # 避免真实高危告警（如命中威胁情报库的恶意IP）被一律误降级为 0% 人工复核
        if confidence is None and (src_ip or title):
            try:
                fallback = await self._rule_based_fallback(
                    src_ip=src_ip,
                    title=title,
                    alert_type=alert.get("alert_type", "") or alert.get("type", ""),
                    severity=alert.get("severity", ""),
                )
                if fallback is not None:
                    confidence = fallback
                    final_result["confidence"] = confidence
                    final_result["confidence_source"] = "rule_based"
                    logger.info(
                        f"规则引擎兜底评估: alert_id={alert_id} 置信度={confidence:.0%} "
                        f"(source=rule_based, 替代LLM解析失败)"
                    )
            except Exception as e:
                logger.warning(f"规则引擎兜底评估异常: {e}")

        # 保守策略：如果 LLM 没有输出标准结构化裁决，则不执行自动操作
        if confidence is None:
            logger.warning(
                f"告警 {alert_id} 未获取到结构化置信度，"
                f"跳过自动处置，标记为人工复核"
            )
            action = "escalated"
            confidence = 0.0
            result = {
                "alert_id": alert_id,
                "status": "processed",
                "confidence": 0.0,
                "action": action,
                "summary": final_result.get("summary", "")[:300],
                "reason": "LLM未输出结构化裁决，保守策略→升级人工复核",
            }
            # 升级通知（含 OpenIM IM 推送）：置信度不足需人工介入
            if self.escalator:
                esc_result = await self.escalator.escalate(
                    incident_id=alert_id,
                    summary=final_result.get("summary", ""),
                    confidence=confidence,
                    reason="LLM未输出结构化裁决，保守策略→升级人工复核",
                )
                result["escalation"] = esc_result
                logger.info(f"  已升级人工: {alert_id} (置信度 {confidence:.0%})")
            # 记录事件
            await self._save_event(alert_id, title, 0.0, "escalated", src_ip)
            return result

        # Step 3: 按置信度自动决策
        action = self._decide_action(confidence, src_ip, alert_id)
        result = {
            "alert_id": alert_id,
            "status": "processed",
            "confidence": confidence,
            "action": action,
            "summary": final_result.get("summary", "")[:300],
        }

        if action == "auto_closed":
            # 自动闭环 — 写入数据库
            await self._save_event(alert_id, title, confidence, "resolved", src_ip)
            logger.info(f"  自动闭环: {alert_id} (置信度 {confidence:.0%})")

        elif action == "auto_blocked":
            # 自动封禁 — 先检查熔断器
            try:
                from backend.security.circuit_breaker import circuit_breaker
                if not circuit_breaker.check():
                    cb_status = circuit_breaker.get_status()
                    logger.warning(
                        f"熔断器已触发，跳过自动封禁 {src_ip}: "
                        f"状态={cb_status['state']}, "
                        f"今日封禁={cb_status['blocks_today']}/{cb_status['daily_limit']}"
                    )
                    result["action"] = "block_skipped_circuit_breaker"
                    result["circuit_breaker"] = cb_status
                    return result

                block_result = await self.orchestrator.tools.execute(
                    "firewall_manage",
                    action="block",
                    ip=src_ip,
                    reason=f"自动封禁: {title}",
                    duration_minutes=120,
                    confidence=confidence,
                )
                result["block_result"] = block_result.data if block_result.success else block_result.error
                await self._save_event(alert_id, title, confidence, "blocked", src_ip)

                # 效果自动验证
                if block_result.success:
                    check = await self.orchestrator.tools.execute(
                        "firewall_manage", action="check", ip=src_ip
                    )
                    result["verified"] = check.data.get("is_blocked", False) if check.success else False
                logger.info(f"  自动封禁: {src_ip} (置信度 {confidence:.0%}): {result.get('verified', '?')}")
            except Exception as e:
                logger.error(f"  自动封禁失败: {e}")
                result["action"] = "block_failed"
                result["error"] = str(e)

        elif action == "escalated":
            # 置信度不足 → 升级通知人工
            if self.escalator:
                esc_result = await self.escalator.escalate(
                    incident_id=alert_id,
                    summary=final_result.get("summary", ""),
                    confidence=confidence,
                    reason=f"置信度 {confidence:.0%} < {self._manual_threshold:.0%}，无法自动判定",
                )
                result["escalation"] = esc_result
                logger.info(f"  已升级人工: {alert_id} (置信度 {confidence:.0%})")
            await self._save_event(alert_id, title, confidence, "escalated", src_ip)

        else:
            # 待观察 — 记录但暂不处置
            await self._save_event(alert_id, title, confidence, "monitoring", src_ip)
            logger.info(f"  标记观察: {alert_id} (置信度 {confidence:.0%})")

        # Prometheus 指标记录
        try:
            _record_alert(action)
        except (ImportError, NameError):
            # Prometheus 客户端未安装或未初始化时静默跳过
            pass

        # ═══════ 跨区域联邦同步：将事件推送到其他区域 ═══════
        try:
            fed = getattr(self.orchestrator, "_federation", None)
            if fed and fed.enabled:
                await fed.add_pending_event({
                    "id": alert_id,
                    "title": title,
                    "severity": result.get("severity", "中危"),
                    "status": "open",
                    "source_ip": src_ip,
                    "description": result.get("summary", title),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })
        except (AttributeError, OSError, RuntimeError):
            logger.warning("联邦事件同步失败", exc_info=True)

        return result

    def _decide_action(self, confidence: float, src_ip: str, alert_id: str) -> str:
        """根据置信度决定处置动作"""
        if confidence >= self._auto_close_threshold:
            return "auto_closed"
        elif confidence >= self._auto_block_threshold:
            if src_ip and src_ip not in ["", "0.0.0.0", "127.0.0.1", "::1"]:
                return "auto_blocked"
            return "monitoring"
        elif confidence < self._manual_threshold:
            return "escalated"
        else:
            return "monitoring"

    # ═══════════════════ 辅助方法 ═══════════════════

    def _normalize_alert(self, raw: dict) -> dict:
        """标准化不同来源的告警格式"""
        alert = {
            "id": raw.get("id", raw.get("alert_id", f"alert-{uuid.uuid4().hex[:8]}")),
            "title": raw.get("title", raw.get("name", raw.get("alert_name", "未知告警"))),
            "description": raw.get("description", raw.get("message", raw.get("text", ""))),
            "src_ip": raw.get("src_ip", raw.get("source_ip", raw.get("ip", ""))),
            "dst_ip": raw.get("dst_ip", raw.get("dest_ip", raw.get("destination_ip", ""))),
            "severity": raw.get("severity", raw.get("level", raw.get("priority", "中危"))),
            "type": raw.get("type", raw.get("alert_type", raw.get("category", "unknown"))),
            "timestamp": raw.get("timestamp", raw.get("time", datetime.now(timezone.utc).isoformat())),
            "raw": raw,
        }
        return alert

    async def _save_event(self, alert_id: str, title: str, confidence: float,
                          status: str, src_ip: str = ""):
        """将事件写入数据库（自动适配 SQLite 和 PostgreSQL）"""
        try:
            from backend.storage.database import Repository, _is_postgres
            db = Repository()
            severity = "低危" if confidence < 0.3 else "中危" if confidence < 0.7 else "高危"
            now = datetime.now(timezone.utc).isoformat()
            if _is_postgres():
                sql = (
                    "INSERT INTO events (id, title, severity, status, source_ip, description, created_at) "
                    "VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING"
                )
            else:
                sql = (
                    "INSERT OR IGNORE INTO events "
                    "(id, title, severity, status, source_ip, description, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)"
                )
            await db.execute(sql, (
                alert_id, title, severity, status, src_ip,
                f"自动分析结果: 置信度 {confidence:.0%}", now,
            ))
            await db.close()
        except Exception as e:
            logger.warning(f"保存事件失败: {e}")

    # ═══════════════════ 外部源消费者 ═══════════════════

    async def _consume_kafka(self, topic: str, bootstrap: str):
        """
        Kafka 消费者 — 真实实现

        从 Kafka 主题消费告警消息，自动标准化后入队处理。

        需要依赖: aiokafka>=0.10.0
        安装: pip install aiokafka

        支持 JSON 和纯文本两种消息格式:
          - JSON: {"title": "...", "src_ip": "...", "description": "..."}
          - 纯文本: 视为 description 字段

        Kafka 配置通过 config.yaml 或环境变量设置:
          auto_operation.ingestion.kafka_topic
          auto_operation.ingestion.kafka_bootstrap
        """
        try:
            from aiokafka import AIOKafkaConsumer
        except ImportError:
            logger.critical(
                "Kafka 消费者需要安装 aiokafka 库。\n"
                "   pip install aiokafka>=0.10.0\n"
                "安装后重新启动即可自动生效。"
            )
            # 不阻塞启动，记录错误后等待
            await asyncio.Event().wait()
            return

        logger.info(f"Kafka 消费者启动: topic={topic}, bootstrap={bootstrap}")

        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=bootstrap,
            group_id="secagentx-ingestor",
            value_deserializer=lambda m: self._deserialize_kafka_msg(m),
            auto_offset_reset="latest",
            enable_auto_commit=True,
            auto_commit_interval_ms=5000,
            session_timeout_ms=30000,
            heartbeat_interval_ms=10000,
        )

        try:
            await consumer.start()
            logger.info(f"Kafka 消费者已连接: {topic}")
            async for msg in consumer:
                value = msg.value
                if value is None:
                    continue

                # 标准化告警格式
                alert = self._normalize_alert(
                    value if isinstance(value, dict) else {"description": str(value)}
                )
                alert["_source"] = "kafka"
                alert["_kafka_topic"] = topic
                alert["_kafka_partition"] = msg.partition
                alert["_kafka_offset"] = msg.offset

                # 统一入队（带去重）
                enqueued = await self._enqueue(alert)
                if enqueued:
                    logger.debug(
                        "Kafka 消息入队: topic=%s partition=%s offset=%s",
                        topic, msg.partition, msg.offset,
                    )

        except asyncio.CancelledError:
            logger.info("Kafka 消费者被取消")
        except Exception as e:
            logger.error(f"Kafka 消费者异常: {e}")
        finally:
            await consumer.stop()
            logger.info("Kafka 消费者已停止")

    @staticmethod
    def _deserialize_kafka_msg(raw) -> Optional[dict]:
        """反序列化 Kafka 消息，兼容 JSON 和纯文本"""
        if raw is None:
            return None
        if isinstance(raw, bytes):
            try:
                return json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {"description": raw.decode("utf-8", errors="ignore")}
        if isinstance(raw, str):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {"description": raw}
        if isinstance(raw, dict):
            return raw
        return {"description": str(raw)}

    async def _listen_syslog(self, port: int):
        """
        Syslog UDP 监听 — 真实实现

        监听 UDP 端口接收 Syslog 消息（RFC 3164 / RFC 5424），
        自动解析后入队处理。

        Syslog 消息格式示例:
          <14>Jun 27 10:30:00 server sshd[12345]: Failed password for root from 45.33.32.156 port 22 ssh2

        支持的模式:
          - RFC 3164 (BSD syslog): <PRI>TIMESTAMP HOSTNAME MSG
          - RFC 5424 (IETF syslog): <PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID STRUCTURED-DATA MSG
          - 纯文本: 整条消息作为 description
        """
        logger.info(f"Syslog UDP 监听启动: port={port}")

        class SyslogProtocol(asyncio.DatagramProtocol):
            """UDP Syslog 协议处理器"""

            def __init__(self, queue: asyncio.Queue, ingestor):
                self.queue = queue
                self.ingestor = ingestor
                self.logger = logging.getLogger("secagentx.syslog")

            def datagram_received(self, data: bytes, addr):
                """收到 UDP 数据报"""
                try:
                    raw_text = data.decode("utf-8", errors="replace").strip()
                    if not raw_text:
                        return

                    alert = self._parse_syslog(raw_text)
                    alert["_source"] = "syslog"
                    alert["_syslog_sender"] = f"{addr[0]}:{addr[1]}"

                    # 非阻塞入队（通过外层 AutoIngestor._enqueue 带去重）
                    asyncio.ensure_future(self.ingestor._enqueue(alert))

                except Exception as e:
                    self.logger.warning(f"Syslog 解析失败: {e}")

            def _parse_syslog(self, raw: str) -> dict:
                """解析 Syslog 消息，提取关键字段"""
                # 尝试提取 PRI 和 时间戳
                alert = {
                    "id": f"syslog-{uuid.uuid4().hex[:8]}",
                    "title": "Syslog Alert",
                    "description": raw[:500],
                    "src_ip": "",
                    "severity": "中危",
                    "type": "syslog",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

                # 提取 PRI (优先级)
                pri_match = re.match(r'<(\d+)>', raw)
                if pri_match:
                    pri = int(pri_match.group(1))
                    facility = pri >> 3
                    severity = pri & 0x07
                    # Syslog severity: 0=emerg, 1=alert, 2=crit, 3=error, 4=warning, 5=notice, 6=info, 7=debug
                    severity_map = {
                        0: "紧急", 1: "紧急", 2: "高危", 3: "高危",
                        4: "中危", 5: "低危", 6: "低危", 7: "低危",
                    }
                    alert["severity"] = severity_map.get(severity, "中危")

                # 提取 IP 地址
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ips = re.findall(ip_pattern, raw)
                # 排除私有IP和本地地址
                for ip in ips:
                    if not ip.startswith(("10.", "172.16", "192.168", "127.", "0.")):
                        alert["src_ip"] = ip
                        break
                if not alert["src_ip"] and ips:
                    alert["src_ip"] = ips[0]

                # 识别常见告警类型
                alert_type_keywords = {
                    "sshd.*Failed password": "SSH暴力破解",
                    "sshd.*Invalid user": "SSH枚举攻击",
                    "pam.*authentication failure": "认证失败",
                    "sudo.*FAILED": "权限提升失败",
                    "iptables.*DROP": "防火墙拦截",
                    "nft.*DROP": "防火墙拦截",
                    "Connection closed by": "连接异常关闭",
                }
                for pattern, alert_type in alert_type_keywords.items():
                    if re.search(pattern, raw, re.IGNORECASE):
                        alert["title"] = alert_type
                        break

                # 提取主机名
                host_match = re.search(r'<.*?>\s*\S+\s+(\S+)\s+', raw)
                if host_match:
                    alert["_syslog_hostname"] = host_match.group(1)

                return alert

        loop = asyncio.get_running_loop()
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: SyslogProtocol(self._queue, self),
                local_addr=("0.0.0.0", port),
            )
            logger.info(f"Syslog UDP 监听已启动: 0.0.0.0:{port}")
            await asyncio.Event().wait()
        except OSError as e:
            logger.error(f"Syslog 端口 {port} 绑定失败: {e}")
            logger.error("请检查端口是否被占用，或使用更高的端口号（>1024）")
        except asyncio.CancelledError:
            logger.info("Syslog 监听被取消")
        finally:
            if 'transport' in locals():
                transport.close()
                logger.info("Syslog 监听已停止")
