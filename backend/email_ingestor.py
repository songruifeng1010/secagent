"""
邮件安全接入器 (EmailIngestor)

职责:
  让企业员工可以直接将可疑邮件转发到指定邮箱，
  SecAgentX 自动收取、解析、分析、处置。

工作流:
  员工转发可疑邮件 → phish@secagentx.com
       │
       ▼  IMAP 轮询
   EmailIngestor.poll()
       │
       ▼  解析邮件
   - 标题/正文/发件人
   - 提取链接/域名/IP/哈希
   - 附件元数据
       │
       ▼  IOC 提取
   extract_iocs() → IPs, domains, urls, hashes
       │
       ▼  送入 AutoIngestor
   ingestor.handle_alert_direct(alert)
       │
       ▼  自动处置
   自动闭环 / 封禁 / 通知

使用方式:
    # 在 main.py 中:
    ingestor = AutoIngestor(orchestrator, escalator, config)
    email_ing = EmailIngestor(ingestor, config)
    asyncio.create_task(email_ing.start())

配置 (.env):
    EMAIL_IMAP_SERVER=imap.company.com
    EMAIL_IMAP_PORT=993
    EMAIL_USERNAME=phish@secagentx.com
    EMAIL_PASSWORD=your-app-password
    EMAIL_MAILBOX=INBOX
    EMAIL_POLL_INTERVAL=60
    EMAIL_PROCESSED_FOLDER=Processed

配置 (config.yaml):
    auto_operation:
      email_ingestion:
        enabled: true
        poll_interval_seconds: 60
        max_email_size_mb: 10
        process_attachments: true
"""

import os
import re
import json
import time
import uuid
import hashlib
import asyncio
import logging
import email
from urllib.parse import urlparse
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

logger = logging.getLogger("secagentx.email")

# ─── IOC 提取模式 ───────────────────────────────────
URL_PATTERN = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w$.+!*\'(),;:@&=?~#%]*)?', re.IGNORECASE)
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# 已知安全域名白名单（避免误报）
SAFE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "cloudflare.com", "github.com", "gitlab.com", "zoom.us",
    "teams.microsoft.com", "sharepoint.com", "office.com",
    "office365.com", "okta.com", "duosecurity.com",
}


class EmailIOCExtractor:
    """从邮件文本中提取威胁指标"""

    @staticmethod
    def extract(text: str) -> dict:
        """提取所有 IOC"""
        # URLs
        urls = list(set(URL_PATTERN.findall(text)))

        # IPs (排除私有IP)
        all_ips = IP_PATTERN.findall(text)
        public_ips = [ip for ip in all_ips if not EmailIOCExtractor._is_private_ip(ip)]

        # Domains (从 URL 中和正文中联合提取)
        all_domains = set()
        # 1. 从 URL 中提取域名
        for url in urls:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname
                if hostname:
                    all_domains.add(hostname.lower())
            except Exception:
                pass
        # 2. 从正文中提取独立域名（不包含 URL 已提取的）
        for d in DOMAIN_PATTERN.findall(text):
            d_lower = d.lower()
            if d_lower not in SAFE_DOMAINS:
                # 如果这个域名已经作为 URL 的一部分被提取了，跳过
                if not any(d_lower in u.lower() for u in urls):
                    all_domains.add(d_lower)
        # 3. 去掉安全域名
        filtered_domains = [d for d in all_domains if d not in SAFE_DOMAINS]

        # Hashes
        hashes = list(set(
            SHA256_PATTERN.findall(text) +
            SHA1_PATTERN.findall(text) +
            MD5_PATTERN.findall(text)
        ))

        # Emails
        sender_emails = list(set(EMAIL_PATTERN.findall(text)))

        return {
            "urls": list(set(urls)),
            "public_ips": list(set(public_ips)),
            "domains": list(set(filtered_domains)),
            "hashes": hashes,
            "emails": sender_emails,
        }

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """判断是否为私有/保留 IP"""
        try:
            parts = [int(p) for p in ip.split(".")]
            if parts[0] == 10: return True
            if parts[0] == 172 and 16 <= parts[1] <= 31: return True
            if parts[0] == 192 and parts[1] == 168: return True
            if parts[0] == 127: return True
            if parts[0] == 0: return True
            if parts[0] == 169 and parts[1] == 254: return True
            return False
        except (ValueError, IndexError):
            return True  # 解析失败当私有处理

    @staticmethod
    def is_suspicious(iocs: dict) -> tuple[bool, str]:
        """
        快速初筛：邮件是否可疑

        返回:
            (is_suspicious: bool, reason: str)
        """
        reasons = []

        # 可疑 URL 数量
        suspicious_urls = [u for u in iocs["urls"] if not any(
            safe in u.lower() for safe in ["google.com", "microsoft.com", "apple.com"]
        )]
        if len(suspicious_urls) >= 2:
            reasons.append(f"包含 {len(suspicious_urls)} 个可疑链接")

        # 公开 IP 出现在正文中（正常邮件很少含公网 IP）
        if iocs["public_ips"]:
            reasons.append(f"包含公网 IP: {', '.join(iocs['public_ips'][:3])}")

        # 未知域名
        if iocs["domains"]:
            reasons.append(f"包含 {len(iocs['domains'])} 个非白名单域名")

        # 文件哈希
        if iocs["hashes"]:
            reasons.append(f"包含 {len(iocs['hashes'])} 个文件哈希")

        if len(reasons) >= 2:
            return True, "; ".join(reasons)

        if len(reasons) == 1 and len(iocs["urls"]) > 0:
            return True, "; ".join(reasons)

        return False, "无明显可疑指标"


class EmailIngestor:
    """
    邮件安全接入器

    从 IMAP 邮箱收取可疑邮件，解析内容并提取 IOC，
    送入 SecAgentX 核心引擎进行安全分析。

    使用示例:
        from backend.email_ingestor import EmailIngestor
        from backend.auto_ingestor import AutoIngestor

        ingestor = AutoIngestor(orchestrator, escalator, config)
        email_ing = EmailIngestor(ingestor, config)
        asyncio.create_task(email_ing.start())
    """

    def __init__(self, auto_ingestor, config: dict = None):
        self.ingestor = auto_ingestor
        self.config = config or {}

        # 邮件配置
        email_cfg = self._get_cfg("email_ingestion", {})

        self.imap_server = os.getenv("EMAIL_IMAP_SERVER", email_cfg.get("imap_server", ""))
        self.imap_port = int(os.getenv("EMAIL_IMAP_PORT", email_cfg.get("imap_port", 993)))
        self.username = os.getenv("EMAIL_USERNAME", email_cfg.get("username", ""))
        self.password = os.getenv("EMAIL_PASSWORD", email_cfg.get("password", ""))
        self.mailbox = os.getenv("EMAIL_MAILBOX", email_cfg.get("mailbox", "INBOX"))
        self.processed_folder = os.getenv(
            "EMAIL_PROCESSED_FOLDER",
            email_cfg.get("processed_folder", "Processed"),
        )
        self.poll_interval = int(os.getenv(
            "EMAIL_POLL_INTERVAL",
            email_cfg.get("poll_interval_seconds", 60),
        ))
        self.max_email_size = int(os.getenv(
            "EMAIL_MAX_SIZE_MB",
            email_cfg.get("max_email_size_mb", 10),
        )) * 1024 * 1024
        self.process_attachments = email_cfg.get("process_attachments", True)

        self._running = False
        self._processed_count = 0
        self._ioc_extractor = EmailIOCExtractor()

        # 验证配置
        self._configured = bool(self.imap_server and self.username and self.password)

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

    async def start(self):
        """启动邮件轮询"""
        if not self._configured:
            logger.warning(
                "邮件接入器未配置 (EMAIL_IMAP_SERVER / USERNAME / PASSWORD)，跳过启动"
            )
            return

        if self._running:
            logger.warning("邮件接入器已在运行")
            return

        self._running = True
        logger.info(
            f"邮件接入器已启动: {self.username}@{self.imap_server}:{self.imap_port}, "
            f"轮询间隔={self.poll_interval}s, "
            f"处理目录='{self.processed_folder}'"
        )

        while self._running:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"邮件轮询异常: {e}", exc_info=True)

            await asyncio.sleep(self.poll_interval)

    async def stop(self):
        """停止邮件轮询"""
        self._running = False
        logger.info("邮件接入器已停止")

    async def _poll_once(self):
        """一次轮询：连接 IMAP → 搜索未读 → 逐封处理"""
        import imaplib

        logger.debug(f"邮件轮询: {self.mailbox} @ {self.imap_server}")

        try:
            # 连接 IMAP（在线程中执行，防止阻塞事件循环）
            conn = await asyncio.to_thread(self._connect_imap)
            if conn is None:
                return

            try:
                # 搜索未读邮件
                status, messages = await asyncio.to_thread(
                    conn.search, None, "UNSEEN"
                )
                if status != "OK":
                    logger.warning(f"IMAP 搜索失败: {status}")
                    return

                email_ids = messages[0].split() if messages[0] else []
                if not email_ids:
                    return

                logger.info(f"发现 {len(email_ids)} 封未读邮件")

                for eid in email_ids:
                    try:
                        await self._process_email(conn, eid)
                    except Exception as e:
                        logger.error(f"处理邮件 {eid} 失败: {e}")
                        continue

            finally:
                # 关闭连接
                try:
                    await asyncio.to_thread(conn.logout)
                except Exception:
                    pass

        except imaplib.IMAP4.error as e:
            logger.error(f"IMAP 连接错误: {e}")
        except Exception as e:
            logger.error(f"邮件轮询异常: {e}")

    def _connect_imap(self):
        """同步连接 IMAP 服务器"""
        import imaplib
        import ssl

        try:
            if self.imap_port == 993:
                # 安全默认：验证服务器证书与主机名。
                ctx = ssl.create_default_context()
                conn = imaplib.IMAP4_SSL(
                    self.imap_server, self.imap_port, ssl_context=ctx
                )
            else:
                conn = imaplib.IMAP4(self.imap_server, self.imap_port)
                conn.starttls()

            conn.login(self.username, self.password)
            conn.select(self.mailbox)
            return conn
        except Exception as e:
            logger.error(f"IMAP 连接失败: {e}")
            return None

    async def _process_email(self, conn, email_id: bytes):
        """处理单封邮件"""
        import imaplib

        eid = email_id.decode() if isinstance(email_id, bytes) else str(email_id)

        # 获取邮件原始内容
        status, msg_data = await asyncio.to_thread(
            conn.fetch, email_id, "(RFC822)"
        )
        if status != "OK":
            logger.warning(f"获取邮件 {eid} 失败: {status}")
            return

        raw_email = msg_data[0][1] if isinstance(msg_data[0], tuple) else msg_data[0]

        # 解析邮件
        parsed = await asyncio.to_thread(self._parse_email, raw_email)
        if parsed is None:
            return

        # 提取 IOC
        iocs = self._ioc_extractor.extract(parsed["body_text"])
        parsed["iocs"] = iocs

        # 快速初筛
        is_suspicious, reason = self._ioc_extractor.is_suspicious(iocs)
        if not is_suspicious:
            logger.info(
                f"邮件初筛安全，跳过: {parsed['subject'][:60]} "
                f"(发件人: {parsed['sender']})"
            )
            await asyncio.to_thread(
                self._move_email, conn, email_id, self.processed_folder
            )
            return

        # 构造告警数据
        alert = self._build_alert(parsed)
        logger.info(
            f"可疑邮件 → 送入分析: {parsed['subject'][:60]} "
            f"(IOC: {len(iocs['urls'])} URLs, "
            f"{len(iocs['domains'])} domains, "
            f"{len(iocs['public_ips'])} IPs) - {reason}"
        )

        # 送入 AutoIngestor 核心分析引擎
        result = await self.ingestor.handle_alert_direct(alert)

        self._processed_count += 1

        # 记录分析结果
        action = result.get("action", "unknown")
        confidence = result.get("confidence", 0)
        logger.info(
            f"邮件分析完成: {parsed['subject'][:60]} "
            f"→ action={action}, confidence={confidence:.0%}"
        )

        # 标记已处理：移至目标目录
        await asyncio.to_thread(
            self._move_email, conn, email_id, self.processed_folder
        )

    def _parse_email(self, raw_bytes: bytes) -> Optional[dict]:
        """解析邮件原始字节"""
        try:
            msg = email.message_from_bytes(raw_bytes)
        except Exception as e:
            logger.warning(f"邮件解析失败: {e}")
            return None

        # 基本信息
        subject = str(email.header.make_header(
            email.header.decode_header(msg.get("Subject", ""))
        ))
        sender = str(email.header.make_header(
            email.header.decode_header(msg.get("From", ""))
        ))
        date_str = msg.get("Date", "")
        message_id = msg.get("Message-ID", "") or str(uuid.uuid4().hex[:12])

        # 日期解析
        try:
            dt = parsedate_to_datetime(date_str)
            received_at = dt.isoformat() if dt else datetime.now(timezone.utc).isoformat()
        except Exception:
            received_at = datetime.now(timezone.utc).isoformat()

        # 正文提取（优先 HTML 去标签，fallback 纯文本）
        body_text = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition:
                    # 附件
                    filename = part.get_filename()
                    if filename:
                        file_data = part.get_payload(decode=True)
                        if file_data:
                            file_hash = hashlib.sha256(file_data).hexdigest()
                            file_size = len(file_data)
                            attachments.append({
                                "filename": filename,
                                "size": file_size,
                                "sha256": file_hash,
                                "content_type": content_type,
                            })
                    continue

                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            body_text += payload.decode("utf-8", errors="replace")
                        except Exception:
                            body_text += payload.decode("latin-1", errors="replace")

                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            html_content = payload.decode("utf-8", errors="replace")
                            body_html = html_content
                            # HTML 去标签得到纯文本
                            body_text += re.sub(r'<[^>]+>', ' ', html_content)
                        except Exception:
                            pass
        else:
            # 非 multipart
            payload = msg.get_payload(decode=True)
            if payload and msg.get_content_type() == "text/plain":
                try:
                    body_text = payload.decode("utf-8", errors="replace")
                except Exception:
                    body_text = payload.decode("latin-1", errors="replace")
            elif payload and "text/html" in msg.get_content_type():
                html_content = payload.decode("utf-8", errors="replace")
                body_html = html_content
                body_text = re.sub(r'<[^>]+>', ' ', html_content)

        # 去空白
        body_text = re.sub(r'\s+', ' ', body_text).strip()[:5000]

        return {
            "message_id": message_id,
            "subject": subject or "(无主题)",
            "sender": sender,
            "received_at": received_at,
            "body_text": body_text,
            "body_html": body_html[:2000] if body_html else "",
            "attachments": attachments,
        }

    def _build_alert(self, parsed: dict) -> dict:
        """将解析后的邮件构造为告警数据"""
        iocs = parsed.get("iocs", {})
        subject = parsed.get("subject", "")
        sender = parsed.get("sender", "")

        # 构建描述
        description_parts = [
            f"[邮件安全检测] 发件人: {sender}",
            f"正文摘要: {parsed.get('body_text', '')[:300]}",
        ]

        if iocs.get("urls"):
            description_parts.append(f"可疑链接: {' '.join(iocs['urls'][:5])}")
        if iocs.get("domains"):
            description_parts.append(f"可疑域名: {' '.join(iocs['domains'][:5])}")
        if iocs.get("public_ips"):
            description_parts.append(f"公网IP: {' '.join(iocs['public_ips'][:3])}")
        if iocs.get("hashes"):
            description_parts.append(f"文件哈希: {' '.join(iocs['hashes'][:3])}")

        # 从附件中提取首个公网 IP 作为 src_ip（如有）
        src_ip = ""
        if iocs.get("public_ips"):
            src_ip = iocs["public_ips"][0]

        # 提取链接中的域名作为 IOC 一并写入描述
        alert = {
            "id": f"email-{uuid.uuid4().hex[:12]}",
            "title": f"[钓鱼邮件] {subject[:80]}",
            "description": "\n".join(description_parts),
            "source_ip": src_ip,
            "src_ip": src_ip,
            "severity": "高危",
            "alert_type": "phishing_email",
            "timestamp": parsed.get("received_at", ""),
            "detail": {
                "sender": sender,
                "subject": subject,
                "message_id": parsed.get("message_id", ""),
                "iocs": iocs,
                "attachments": parsed.get("attachments", []),
            },
        }

        return alert

    def _move_email(self, conn, email_id, target_folder: str):
        """将邮件移动到目标目录"""
        import imaplib

        eid = email_id.decode() if isinstance(email_id, bytes) else str(email_id)

        try:
            # 确保目标目录存在
            conn.create(target_folder)
        except imaplib.IMAP4.error:
            pass  # 目录已存在

        try:
            conn.copy(email_id, target_folder)
            conn.store(email_id, "+FLAGS", "\\Deleted")
            conn.expunge()
        except Exception as e:
            logger.warning(f"移动邮件 {eid} 失败: {e}")

    def get_stats(self) -> dict:
        """获取处理统计"""
        return {
            "configured": self._configured,
            "running": self._running,
            "processed_count": self._processed_count,
            "imap_server": self.imap_server,
            "poll_interval": self.poll_interval,
        }
