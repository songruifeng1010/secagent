"""
自动升级通知引擎 (AutoEscalation)

职责:
  当置信度低于阈值时，通过多通道自动通知人工介入。

支持通道:
  - Console: 控制台输出（默认启用）
  - Slack Webhook: 发送 Slack 消息
  - 钉钉机器人: 发送钉钉消息
  - 通用 Webhook: 对接企业已有告警平台

使用方式:
    escalator = AutoEscalation(config.get("auto_operation", {}))
    await escalator.escalate(
        incident_id="inc-xxxx",
        summary="分析摘要",
        confidence=0.25,
        reason="多源威胁情报不一致，无法判定",
    )
"""
import os
import json
import time
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("secagentx.escalation")


class EscalationChannel:
    """升级通知通道基类"""

    def __init__(self, config: dict):
        self.enabled = config.get("enabled", False)
        self.config = config

    async def send(self, title: str, body: str, incident_id: str = "",
                   confidence: float = 0.0) -> bool:
        """发送通知，返回是否成功"""
        raise NotImplementedError


class ConsoleChannel(EscalationChannel):
    """控制台输出通道（默认启用，无需额外配置）"""

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config or {"enabled": True})

    async def send(self, title: str, body: str, incident_id: str = "",
                   confidence: float = 0.0) -> bool:
        separator = "=" * 60
        msg = (
            f"\n{separator}\n"
            f"  [ESCALATION] 需要人工介入\n"
            f"  Incident: {incident_id}\n"
            f"  置信度: {confidence:.0%}\n"
            f"  标题: {title}\n"
            f"  详情:\n{body}\n"
            f"{separator}\n"
        )
        logger.warning(f"[ESCALATION] {incident_id} 置信度={confidence:.0%} 标题={title}")
        # 控制台已有 StreamHandler 输出，无需 print
        return True


class SlackChannel(EscalationChannel):
    """Slack Webhook 通知通道"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url", "") or os.getenv("SLACK_WEBHOOK_URL", "")

    async def send(self, title: str, body: str, incident_id: str = "",
                   confidence: float = 0.0) -> bool:
        if not self.webhook_url:
            logger.warning("Slack webhook URL 未配置，跳过 Slack 通知")
            return False

        try:
            import httpx
            color = "#FF0000" if confidence < 0.3 else "#FFA500"
            payload = {
                "attachments": [{
                    "color": color,
                    "title": title,
                    "text": body,
                    "fields": [
                        {"title": "事件ID", "value": incident_id, "short": True},
                        {"title": "置信度", "value": f"{confidence:.0%}", "short": True},
                        {"title": "时间", "value": datetime.now(timezone.utc).isoformat(), "short": False},
                    ],
                }]
            }
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self.webhook_url, json=payload)
                resp.raise_for_status()
                logger.info(f"Slack 通知成功: {incident_id}")
                return True
        except Exception as e:
            logger.error(f"Slack 通知失败: {e}")
            return False


class DingTalkChannel(EscalationChannel):
    """钉钉机器人通知通道"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.token = config.get("token", "") or os.getenv("DINGTALK_TOKEN", "")

    async def send(self, title: str, body: str, incident_id: str = "",
                   confidence: float = 0.0) -> bool:
        if not self.token:
            logger.warning("钉钉 token 未配置，跳过钉钉通知")
            return False

        try:
            import httpx
            url = f"https://oapi.dingtalk.com/robot/send?access_token={self.token}"
            payload = {
                "msgtype": "markdown",
                "markdown": {
                    "title": title,
                    "text": (
                        f"# {title}\n\n"
                        f"**事件ID**: {incident_id}\n"
                        f"**置信度**: {confidence:.0%}\n"
                        f"**时间**: {datetime.now(timezone.utc).isoformat()}\n\n"
                        f"---\n{body}"
                    ),
                },
            }
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                logger.info(f"钉钉通知成功: {incident_id}")
                return True
        except Exception as e:
            logger.error(f"钉钉通知失败: {e}")
            return False


class WebhookChannel(EscalationChannel):
    """通用 Webhook 通知通道（对接企业已有告警平台）"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.url = config.get("url", "") or os.getenv("ESCALATION_WEBHOOK_URL", "")

    async def send(self, title: str, body: str, incident_id: str = "",
                   confidence: float = 0.0) -> bool:
        if not self.url:
            logger.warning("Webhook URL 未配置，跳过 Webhook 通知")
            return False

        try:
            import httpx
            payload = {
                "event": "secagentx.escalation",
                "incident_id": incident_id,
                "title": title,
                "body": body,
                "confidence": confidence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self.url, json=payload)
                resp.raise_for_status()
                logger.info(f"Webhook 通知成功: {incident_id}")
                return True
        except Exception as e:
            logger.error(f"Webhook 通知失败: {e}")
            return False


class OpenIMChannel(EscalationChannel):
    """
    OpenIM 即时通讯通知通道（本地化部署）

    将 SecAgentX 的安全告警/升级通知推送到 OpenIM 群组，
    使安全运营人员能在 IM 中实时收到告警。

    配置示例 (config.yaml):
        - type: openim                # OpenIM 通道
          enabled: true
          api_url: "http://localhost:10002"     # OpenIM API 地址
          secret: "${OPENIM_SECRET}"            # OpenIM 应用密钥
          admin_user_id: "imAdmin"              # 管理员账号
          group_id: "sec-agentx-alerts"         # 目标群组
          # 可选：token 缓存刷新（秒）
          token_ttl: 7200

    说明:
      - 使用 OpenIM 管理员 token 发送消息（/auth/get_admin_token）
      - 消息类型为群聊文本消息（sessionType=3, contentType=101）
      - token 会缓存复用，过期后自动刷新
    """

    # 群聊会话类型
    GROUP_CHAT_TYPE = 3
    # 文本消息类型
    TEXT_CONTENT_TYPE = 101
    # 服务端消息来源
    MSG_FROM = 100

    def __init__(self, config: dict):
        super().__init__(config)
        self.api_url = (config.get("api_url", "") or os.getenv("OPENIM_API_URL", "http://localhost:10002")).rstrip("/")
        self.secret = config.get("secret", "") or os.getenv("OPENIM_SECRET", "")
        self.admin_user_id = config.get("admin_user_id", "") or os.getenv("OPENIM_ADMIN_USER_ID", "imAdmin")
        self.group_id = config.get("group_id", "") or os.getenv("OPENIM_GROUP_ID", "")
        self.token_ttl = int(config.get("token_ttl", 7200))

        self._token: str = ""
        self._token_expire: float = 0.0
        self._token_lock = asyncio.Lock()

    async def _get_admin_token(self) -> str:
        """获取（或缓存复用）OpenIM 管理员 token"""
        if not self.secret:
            raise RuntimeError("OpenIM 已启用，但 OPENIM_SECRET 未配置")
        now = time.time()
        if self._token and now < self._token_expire:
            return self._token

        async with self._token_lock:
            # 双重检查，防止并发重复获取
            if self._token and time.time() < self._token_expire:
                return self._token

            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{self.api_url}/auth/get_admin_token",
                    json={"secret": self.secret, "userID": self.admin_user_id, "platform": 10},
                    headers={"operationID": f"secagentx-token-{int(time.time())}"},
                )
                resp.raise_for_status()
                data = resp.json()
                if data.get("errCode", 0) != 0:
                    logger.error(f"获取 OpenIM 管理员 token 失败: {data}")
                    raise RuntimeError(f"OpenIM token 获取失败: {data.get('errMsg')}")

                token = data["data"]["token"]
                expire_seconds = data["data"].get("expireTimeSeconds", self.token_ttl)
                # 提前 10% 时间刷新，避免边界过期
                self._token = token
                self._token_expire = time.time() + max(60, int(expire_seconds * 0.9))
                logger.debug(f"OpenIM 管理员 token 已获取 (有效期 {expire_seconds}s)")
                return token

    async def send(self, title: str, body: str, incident_id: str = "",
                   confidence: float = 0.0) -> bool:
        if not self.group_id:
            logger.warning("OpenIM 群组未配置（group_id），跳过 OpenIM 通知")
            return False

        try:
            token = await self._get_admin_token()

            # 构造告警卡片消息（结构化文本）
            level = "🔴" if confidence < 0.3 else "🟠"
            ts = datetime.now(timezone.utc).isoformat()
            msg_text = (
                f"{level} 【SecAgentX 安全告警】\n"
                f"━━━━━━━━━━━━━━━━\n"
                f"📌 标题: {title}\n"
                f"🆔 事件ID: {incident_id or '-'}\n"
                f"📊 置信度: {confidence:.0%}\n"
                f"🕐 时间: {ts}\n"
                f"━━━━━━━━━━━━━━━━\n"
                f"📄 详情:\n{body[:800]}"
            )

            import httpx
            payload = {
                "recvID": self.group_id,
                "sendID": self.admin_user_id,
                "groupID": self.group_id,
                "senderPlatformID": 10,
                "clientMsgID": f"secagentx-{incident_id or 'alert'}-{int(time.time() * 1000)}",
                "serverMsgID": "",
                "msgFrom": self.MSG_FROM,
                "msgType": self.TEXT_CONTENT_TYPE,
                "content": {"content": msg_text},
                "sessionType": self.GROUP_CHAT_TYPE,
                "contentType": self.TEXT_CONTENT_TYPE,
                "createTime": int(time.time() * 1000),
                "status": 0,
            }
            headers = {
                "operationID": f"secagentx-{incident_id or 'alert'}-{int(time.time())}",
                "token": token,
            }

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{self.api_url}/msg/send_msg",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
                if data.get("errCode", 0) != 0:
                    # 如果 token 失效，清空缓存重试一次
                    if data.get("errCode") in (1101, 1102, 1103):  # token 相关错误
                        self._token = ""
                        self._token_expire = 0.0
                        logger.warning(f"OpenIM token 失效，清空缓存: {data}")
                        return False
                    logger.error(f"OpenIM 发送消息失败: {data}")
                    return False

                logger.info(f"OpenIM 告警通知成功: {incident_id} -> 群组 {self.group_id}")
                return True

        except Exception as e:
            logger.error(f"OpenIM 通知失败: {e}")
            return False


# 通道注册表
CHANNEL_REGISTRY = {
    "console": ConsoleChannel,
    "slack": SlackChannel,
    "dingtalk": DingTalkChannel,
    "webhook": WebhookChannel,
    "openim": OpenIMChannel,
}


class AutoEscalation:
    """
    自动升级通知引擎

    使用示例:
        config = load_config().get("auto_operation", {})
        escalator = AutoEscalation(config)
        await escalator.escalate("inc-xxx", "分析摘要", 0.25, "置信度不足")
    """

    def __init__(self, auto_op_config: dict = None):
        self.config = auto_op_config or {}
        self._channels: list[EscalationChannel] = []
        self._last_notify: dict[str, float] = {}  # incident_id -> timestamp
        self._init_channels()

    def _init_channels(self):
        """初始化所有启用的通知通道"""
        escalation_cfg = self.config.get("escalation", {})
        channels_cfg = escalation_cfg.get("channels", [])

        self._min_interval = escalation_cfg.get("min_interval_seconds", 300)

        if not channels_cfg:
            # 默认启用控制台
            self._channels.append(ConsoleChannel())

        for ch_cfg in channels_cfg:
            ch_type = ch_cfg.get("type", "")
            ch_class = CHANNEL_REGISTRY.get(ch_type)
            if ch_class:
                try:
                    channel = ch_class(ch_cfg)
                    if channel.enabled:
                        self._channels.append(channel)
                except Exception as e:
                    logger.warning(f"初始化通道 {ch_type} 失败: {e}")

        # 确保至少有控制台输出
        if not any(isinstance(c, ConsoleChannel) for c in self._channels):
            self._channels.append(ConsoleChannel())

    async def escalate(self, incident_id: str, summary: str,
                       confidence: float, reason: str = "") -> dict:
        """
        发送自动升级通知到所有启用的通道

        参数:
            incident_id: 事件 ID
            summary: 分析摘要
            confidence: 当前置信度
            reason: 升级原因

        返回:
            {"success": bool, "channels": int, "details": [...]}
        """
        # ═══════ 防刷保护：同一事件在最小间隔内不重复通知 ═══════
        now = time.time()
        last = self._last_notify.get(incident_id, 0)
        if now - last < self._min_interval:
            logger.debug(f"跳过通知 {incident_id}：距上次通知仅 {now - last:.0f}s < {self._min_interval}s")
            return {"success": True, "skipped": True, "reason": "min_interval"}

        self._last_notify[incident_id] = now

        title = (
            f"[SecAgentX] [ATTENTION] 需要人工介入 ({confidence:.0%})"
            if confidence < 0.3
            else f"[SecAgentX] 置信度待提升 ({confidence:.0%})"
        )

        body = (
            f"**事件 ID**: {incident_id}\n"
            f"**置信度**: {confidence:.0%}\n"
            f"**升级原因**: {reason or '置信度低于自动处置阈值'}\n"
            f"**分析摘要**:\n{summary[:500]}\n"
            f"**时间**: {datetime.now(timezone.utc).isoformat()}\n"
        )

        # 并行发送到所有通道
        results = []
        tasks = []
        for ch in self._channels:
            tasks.append(ch.send(
                title=title, body=body,
                incident_id=incident_id, confidence=confidence,
            ))

        channel_results = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = 0
        details = []
        for ch, result in zip(self._channels, channel_results):
            ch_name = ch.__class__.__name__.replace("Channel", "")
            if isinstance(result, Exception):
                logger.error(f"通道 {ch_name} 通知异常: {result}")
                details.append({"channel": ch_name, "success": False, "error": str(result)})
            elif result:
                success_count += 1
                details.append({"channel": ch_name, "success": True})
            else:
                details.append({"channel": ch_name, "success": False, "error": "发送失败"})

        return {
            "success": success_count > 0,
            "channels": success_count,
            "total_channels": len(self._channels),
            "details": details,
        }

    def get_status(self) -> list[dict]:
        """获取各通道状态"""
        return [
            {
                "type": ch.__class__.__name__.replace("Channel", "").lower(),
                "enabled": ch.enabled,
            }
            for ch in self._channels
        ]
