"""
EmailIngestor 单元测试

测试覆盖:
  - IOC 提取 (URLs/IPs/Domains/Hashes)
  - 私有 IP 过滤
  - 安全域名白名单
  - 可疑度初筛
  - 邮件解析
  - 告警构造
  - 完整流程集成 (Mock IMAP)
"""
import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestEmailIOCExtractor:
    """IOC 提取器单元测试"""

    def setup_method(self):
        from backend.email_ingestor import EmailIOCExtractor
        self.extractor = EmailIOCExtractor()

    def test_extract_urls(self):
        """测试：从文本中提取 URL"""
        text = "请点击 http://evil.com/login 或 https://malware.net/download?file=1"
        iocs = self.extractor.extract(text)
        assert "http://evil.com/login" in iocs["urls"]
        assert "https://malware.net/download?file=1" in iocs["urls"]
        assert len(iocs["urls"]) == 2

    def test_extract_public_ips(self):
        """测试：提取公网 IP，过滤私有 IP"""
        text = "来源IP: 45.33.32.156, 内网: 10.0.0.1, 本地: 127.0.0.1"
        iocs = self.extractor.extract(text)
        assert "45.33.32.156" in iocs["public_ips"]
        assert "10.0.0.1" not in iocs["public_ips"]
        assert "127.0.0.1" not in iocs["public_ips"]

    def test_extract_domains_filter_safe(self):
        """测试：提取域名时过滤安全域名"""
        text = "访问 google.com 或 evil.com 或 microsoft-share.com"
        iocs = self.extractor.extract(text)
        assert "google.com" not in iocs["domains"]  # 安全域名应被过滤
        assert "evil.com" in iocs["domains"]
        assert "microsoft-share.com" in iocs["domains"]

    def test_extract_hashes(self):
        """测试：提取文件哈希"""
        text = (
            "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
            "MD5: d41d8cd98f00b204e9800998ecf8427e"
        )
        iocs = self.extractor.extract(text)
        assert len(iocs["hashes"]) >= 1
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs["hashes"]

    def test_private_ip_filtering(self):
        """测试：私有IP判断"""
        from backend.email_ingestor import EmailIOCExtractor
        assert EmailIOCExtractor._is_private_ip("10.0.0.1") is True
        assert EmailIOCExtractor._is_private_ip("172.16.0.1") is True
        assert EmailIOCExtractor._is_private_ip("192.168.1.1") is True
        assert EmailIOCExtractor._is_private_ip("127.0.0.1") is True
        assert EmailIOCExtractor._is_private_ip("8.8.8.8") is False
        assert EmailIOCExtractor._is_private_ip("45.33.32.156") is False

    def test_empty_text(self):
        """测试：空文本不报错"""
        iocs = self.extractor.extract("")
        assert iocs["urls"] == []
        assert iocs["public_ips"] == []
        assert iocs["domains"] == []

    def test_normal_email_no_ioc(self):
        """测试：正常邮件（不含可疑指标）"""
        text = "Hi team, please find the meeting notes attached. Thanks!"
        iocs = self.extractor.extract(text)
        assert len(iocs["urls"]) == 0
        assert len(iocs["public_ips"]) == 0
        assert len(iocs["domains"]) == 0

    def test_is_suspicious_true(self):
        """测试：可疑度初筛 — 判定为可疑"""
        from backend.email_ingestor import EmailIOCExtractor
        iocs = {
            "urls": ["http://evil.com/login"],
            "public_ips": ["45.33.32.156"],
            "domains": ["evil.com"],
            "hashes": [],
            "emails": [],
        }
        suspicious, reason = EmailIOCExtractor.is_suspicious(iocs)
        assert suspicious is True
        assert len(reason) > 0

    def test_is_suspicious_false(self):
        """测试：可疑度初筛 — 判定为安全"""
        from backend.email_ingestor import EmailIOCExtractor
        iocs = {
            "urls": [],
            "public_ips": [],
            "domains": [],
            "hashes": [],
            "emails": ["user@company.com"],
        }
        suspicious, reason = EmailIOCExtractor.is_suspicious(iocs)
        assert suspicious is False


class TestEmailParsing:
    """邮件解析单元测试"""

    def test_parse_simple_email(self):
        """测试：解析简单纯文本邮件"""
        from backend.email_ingestor import EmailIngestor
        from backend.auto_ingestor import AutoIngestor
        from email.mime.text import MIMEText

        msg = MIMEText(
            "您好，我们检测到您的账户有异常登录。\n"
            "请点击以下链接验证：http://evil.com/verify\n"
            "来源IP: 45.33.32.156\n",
            _charset="utf-8",
        )
        msg["From"] = "attacker@evil.com"
        msg["To"] = "victim@company.com"
        msg["Subject"] = "您的账户异常登录"
        msg["Date"] = "Mon, 08 Jul 2026 10:00:00 +0800"
        msg["Message-ID"] = "<test123@evil.com>"
        raw_bytes = msg.as_bytes()

        # 使用 Mock AutoIngestor
        mock_ingestor = MagicMock()
        mock_ingestor.handle_alert_direct = AsyncMock(return_value={
            "action": "auto_blocked", "confidence": 0.85, "status": "processed",
        })

        ingestor = EmailIngestor(mock_ingestor, {})
        parsed = ingestor._parse_email(raw_bytes)

        assert parsed is not None
        assert "账户异常登录" in parsed["subject"]
        assert "attacker@evil.com" in parsed["sender"]
        assert "http://evil.com/verify" in parsed["body_text"]
        assert parsed["message_id"] == "<test123@evil.com>"

    def test_parse_multipart_html_email(self):
        """测试：解析 HTML 格式邮件"""
        from backend.email_ingestor import EmailIngestor
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart("alternative")
        msg["From"] = "attacker@evil.com"
        msg["To"] = "victim@company.com"
        msg["Subject"] = "重要通知"
        msg["Date"] = "Mon, 08 Jul 2026 10:00:00 +0800"

        msg.attach(MIMEText("请点击链接验证您的账户 http://evil.com", "plain", "utf-8"))
        msg.attach(MIMEText(
            "<html><body><h1>重要通知</h1><a href='http://evil.com'>验证账户</a></body></html>",
            "html", "utf-8",
        ))

        raw_bytes = msg.as_bytes()

        mock_ingestor = MagicMock()
        ingestor = EmailIngestor(mock_ingestor, {})
        parsed = ingestor._parse_email(raw_bytes)

        assert parsed is not None
        assert "重要通知" in parsed["subject"]
        assert "http://evil.com" in parsed["body_text"]
        assert parsed["attachments"] == []  # 无附件

    def test_parse_email_with_attachment(self):
        """测试：解析含附件的邮件"""
        from backend.email_ingestor import EmailIngestor
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.base import MIMEBase
        from email import encoders

        msg = MIMEMultipart("mixed")
        msg["From"] = "attacker@evil.com"
        msg["To"] = "victim@company.com"
        msg["Subject"] = "发票信息"
        msg["Date"] = "Mon, 08 Jul 2026 10:00:00 +0800"
        msg.attach(MIMEText("请查收附件中的发票信息", "plain", "utf-8"))

        att = MIMEBase("application", "pdf")
        att.set_payload(b"FAKE_PDF_CONTENT_HERE")
        encoders.encode_base64(att)
        att.add_header("Content-Disposition", "attachment", filename="invoice.pdf")
        msg.attach(att)

        raw_bytes = msg.as_bytes()

        mock_ingestor = MagicMock()
        ingestor = EmailIngestor(mock_ingestor, {})
        parsed = ingestor._parse_email(raw_bytes)

        assert parsed is not None
        assert len(parsed["attachments"]) == 1
        assert parsed["attachments"][0]["filename"] == "invoice.pdf"
        assert parsed["attachments"][0]["sha256"] is not None
        assert len(parsed["attachments"][0]["sha256"]) == 64  # SHA256 hex

    def test_build_alert(self):
        """测试：告警构造"""
        from backend.email_ingestor import EmailIngestor

        parsed = {
            "message_id": "<test@evil.com>",
            "subject": "测试钓鱼邮件",
            "sender": "attacker@evil.com",
            "received_at": "2026-07-08T10:00:00+00:00",
            "body_text": "请点击链接 http://evil.com 验证账户",
            "body_html": "",
            "attachments": [],
            "iocs": {
                "urls": ["http://evil.com"],
                "public_ips": ["45.33.32.156"],
                "domains": ["evil.com"],
                "hashes": [],
                "emails": ["attacker@evil.com"],
            },
        }

        mock_ingestor = MagicMock()
        ingestor = EmailIngestor(mock_ingestor, {})
        alert = ingestor._build_alert(parsed)

        assert alert["title"] == "[钓鱼邮件] 测试钓鱼邮件"
        assert alert["alert_type"] == "phishing_email"
        assert alert["severity"] == "高危"
        assert alert["src_ip"] == "45.33.32.156"
        assert alert["detail"]["sender"] == "attacker@evil.com"
        assert alert["detail"]["iocs"]["urls"] == ["http://evil.com"]


class TestEmailIngestorIntegration:
    """集成测试 — 使用 Mock IMAP"""

    @pytest.mark.asyncio
    async def test_full_flow_phishing_email(self):
        """测试：完整流程 — 钓鱼邮件自动封禁"""
        from backend.email_ingestor import EmailIngestor

        # Mock 告警接入器
        mock_ingestor = MagicMock()
        mock_ingestor.handle_alert_direct = AsyncMock(return_value={
            "action": "auto_blocked",
            "confidence": 0.92,
            "status": "processed",
            "alert_id": "email-test-001",
        })

        ingestor = EmailIngestor(mock_ingestor, {})
        ingestor.imap_server = "imap.test.com"
        ingestor.username = "test@test.com"
        ingestor.password = "test-pass"

        # 模拟一封钓鱼邮件（使用 MIMEText 确保正确编码）
        from email.mime.text import MIMEText
        phishing_msg = MIMEText(
            "您的账户因异常登录已被锁定，请立即验证：\n"
            "http://evil-phish.com/verify\n"
            "http://steal-info.net/login\n"
            "IP: 185.220.101.42\n",
            _charset="utf-8",
        )
        phishing_msg["From"] = "phisher@evil.com"
        phishing_msg["To"] = "test@company.com"
        phishing_msg["Subject"] = "您的账户已被锁定"
        phishing_msg["Date"] = "Mon, 08 Jul 2026 10:00:00 +0800"
        phishing_msg["Message-ID"] = "<phish001@evil.com>"

        parsed = ingestor._parse_email(phishing_msg.as_bytes())
        assert parsed is not None

        # 提取 IOC
        from backend.email_ingestor import EmailIOCExtractor
        iocs = EmailIOCExtractor.extract(parsed["body_text"])
        assert len(iocs["urls"]) == 2
        assert len(iocs["domains"]) >= 2

        # 初筛
        suspicious, reason = EmailIOCExtractor.is_suspicious(iocs)
        assert suspicious is True

        # 构造告警
        parsed["iocs"] = iocs
        alert = ingestor._build_alert(parsed)
        assert "phisher@evil.com" in alert["description"]

        # 送入分析引擎
        result = await mock_ingestor.handle_alert_direct(alert)
        assert result["action"] == "auto_blocked"
        assert result["confidence"] >= 0.90

    @pytest.mark.asyncio
    async def test_full_flow_clean_email(self):
        """测试：完整流程 — 正常邮件不触发分析"""
        from backend.email_ingestor import EmailIngestor, EmailIOCExtractor

        mock_ingestor = MagicMock()
        mock_ingestor.handle_alert_direct = AsyncMock()

        ingestor = EmailIngestor(mock_ingestor, {})

        # 正常邮件
        raw_email = (
            "From: hr@company.com\r\n"
            "To: staff@company.com\r\n"
            "Subject: 下周团建通知\r\n"
            "Date: Mon, 08 Jul 2026 10:00:00 +0800\r\n"
            "Message-ID: <hr-001@company.com>\r\n"
            "\r\n"
            "Hi all，下周五公司组织团建活动，请大家准时参加。\r\n"
        )

        parsed = ingestor._parse_email(raw_email.encode())
        assert parsed is not None

        # IOC 提取 — 应无任何异常指标
        iocs = EmailIOCExtractor.extract(parsed["body_text"])
        assert len(iocs["urls"]) == 0
        assert len(iocs["public_ips"]) == 0

        # 初筛 — 应判定为安全
        suspicious, reason = EmailIOCExtractor.is_suspicious(iocs)
        assert suspicious is False

        # 不应调用分析引擎
        mock_ingestor.handle_alert_direct.assert_not_called()

    @pytest.mark.asyncio
    async def test_config_validation(self):
        """测试：配置验证"""
        from backend.email_ingestor import EmailIngestor

        # 未配置
        ingestor = EmailIngestor(MagicMock(), {})
        assert ingestor._configured is False

        # 配置完整
        os.environ["EMAIL_IMAP_SERVER"] = "imap.test.com"
        os.environ["EMAIL_USERNAME"] = "test@test.com"
        os.environ["EMAIL_PASSWORD"] = "pass"
        ingestor2 = EmailIngestor(MagicMock(), {})
        assert ingestor2._configured is True

        # 清理环境变量
        del os.environ["EMAIL_IMAP_SERVER"]
        del os.environ["EMAIL_USERNAME"]
        del os.environ["EMAIL_PASSWORD"]

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """测试：统计信息"""
        from backend.email_ingestor import EmailIngestor

        ingestor = EmailIngestor(MagicMock(), {})
        stats = ingestor.get_stats()
        assert "configured" in stats
        assert "running" in stats
        assert "processed_count" in stats
        assert "imap_server" in stats
        assert "poll_interval" in stats
