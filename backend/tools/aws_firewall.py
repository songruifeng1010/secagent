"""
AWS WAF / Security Group 防火墙适配器

通过 AWS SDK (boto3) 管理安全组规则，实现 IP 封禁/解封。

环境变量:
  AWS_ACCESS_KEY_ID        — AWS Access Key ID
  AWS_SECRET_ACCESS_KEY    — AWS Secret Access Key
  AWS_REGION               — AWS 区域（默认 us-east-1）
  AWS_SECURITY_GROUP_ID    — 安全组 ID（必填）
  AWS_USE_WAF              — 设为 true 则使用 WAF IP Set（默认 false，用安全组）

注意:
  - 需要对安全组有 "AuthorizeSecurityGroupIngress" 和 "RevokeSecurityGroupIngress" 权限
  - 建议使用 IAM 角色，授予最小权限
  - 如果使用 WAF，需额外 WAF 相关权限
"""

import os
import json
import time
import logging
from datetime import datetime, timezone
from typing import Optional
from .base import FirewallAdapter

logger = logging.getLogger("secagentx.firewall.aws")


class AWSFirewallAdapter(FirewallAdapter):
    """
    AWS 安全组 / WAF 防火墙后端

    默认使用安全组（Security Group）实现 IP 封禁。
    可通过 AWS_USE_WAF=true 切换到 WAF IP Set 方式。

    如何获取安全组 ID:
      1. 登录 AWS 控制台 → EC2 → 安全组
      2. 找到目标安全组，复制 ID（如 sg-xxxxxxxxxxxxx）
      3. 配置在 .env: AWS_SECURITY_GROUP_ID=sg-xxxxxxxxxxxxx
    """

    def __init__(self):
        self.access_key_id = os.getenv("AWS_ACCESS_KEY_ID", "")
        self.secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY", "")
        self.region = os.getenv("AWS_REGION", "us-east-1")
        self.security_group_id = os.getenv("AWS_SECURITY_GROUP_ID", "")
        self.use_waf = os.getenv("AWS_USE_WAF", "false").lower() == "true"
        self.waf_ip_set_id = os.getenv("AWS_WAF_IP_SET_ID", "")
        self.waf_ip_set_name = os.getenv("AWS_WAF_IP_SET_NAME", "SecAgentX-Blacklist")

        self._sg_client = None
        self._waf_client = None
        self._has_credentials = bool(
            self.access_key_id and self.secret_access_key and self.security_group_id
        )
        self._cached_rules: list[dict] = []
        self._cache_time = 0.0

    @property
    def sg_client(self):
        """延迟初始化 EC2 Client（安全组）"""
        if self._sg_client is None and self._has_credentials and not self.use_waf:
            try:
                import boto3
                self._sg_client = boto3.client(
                    "ec2",
                    region_name=self.region,
                    aws_access_key_id=self.access_key_id,
                    aws_secret_access_key=self.secret_access_key,
                )
            except ImportError:
                logger.critical("AWS SDK 未安装。请执行: pip install boto3")
                raise
            except Exception as e:
                logger.error(f"AWS EC2 客户端初始化失败: {e}")
                raise
        return self._sg_client

    @property
    def waf_client(self):
        """延迟初始化 WAF Client"""
        if self._waf_client is None and self._has_credentials and self.use_waf:
            try:
                import boto3
                self._waf_client = boto3.client(
                    "wafv2",
                    region_name=self.region,
                    aws_access_key_id=self.access_key_id,
                    aws_secret_access_key=self.secret_access_key,
                )
            except ImportError:
                logger.critical("AWS SDK 未安装。请执行: pip install boto3")
                raise
            except Exception as e:
                logger.error(f"AWS WAF 客户端初始化失败: {e}")
                raise
        return self._waf_client

    async def block_ip(self, ip: str, reason: str = "",
                        duration_minutes: int = 120) -> tuple[bool, str]:
        """封禁 IP"""
        if not self._has_credentials:
            return False, "AWS 凭证未配置（AWS_ACCESS_KEY_ID / SECRET）"

        if self.use_waf:
            return await self._block_ip_waf(ip, reason)
        return await self._block_ip_sg(ip, reason)

    async def _block_ip_sg(self, ip: str, reason: str) -> tuple[bool, str]:
        """通过安全组封禁 IP"""
        try:
            import asyncio

            def _do_block():
                return self.sg_client.authorize_security_group_ingress(
                    GroupId=self.security_group_id,
                    IpPermissions=[{
                        "IpProtocol": "-1",
                        "FromPort": -1,
                        "ToPort": -1,
                        "IpRanges": [{
                            "CidrIp": f"{ip}/32",
                            "Description": f"SecAgentX: {reason[:240]}" if reason else "SecAgentX: auto-block",
                        }],
                    }],
                )

            resp = await asyncio.to_thread(_do_block)
            logger.info(f"AWS 安全组封禁成功: ip={ip}, sg={self.security_group_id}")
            self._cached_rules = []
            self._cache_time = 0.0
            return True, ""

        except Exception as e:
            err_str = str(e)
            if "InvalidPermission.Duplicate" in err_str:
                return True, "rule already exists"
            logger.error(f"AWS 安全组封禁失败: {ip}: {e}")
            return False, f"AWS 安全组封禁失败: {err_str[:200]}"

    async def _block_ip_waf(self, ip: str, reason: str) -> tuple[bool, str]:
        """通过 WAF IP Set 封禁 IP"""
        try:
            import asyncio

            def _do_block():
                # 获取当前的 IP Set
                resp = self.waf_client.get_ip_set(
                    Name=self.waf_ip_set_name,
                    Scope="REGIONAL",
                    Id=self.waf_ip_set_id,
                )
                lock_token = resp["LockToken"]
                current_addresses = resp["IPSet"]["Addresses"]

                # 添加新 IP
                new_addresses = current_addresses + [f"{ip}/32"]

                # 更新 IP Set
                update_resp = self.waf_client.update_ip_set(
                    Name=self.waf_ip_set_name,
                    Scope="REGIONAL",
                    Id=self.waf_ip_set_id,
                    LockToken=lock_token,
                    Addresses=new_addresses,
                )
                return update_resp["LockToken"]

            lock_token = await asyncio.to_thread(_do_block)
            logger.info(f"AWS WAF 封禁成功: ip={ip}, ip_set={self.waf_ip_set_id}")
            self._cached_rules = []
            self._cache_time = 0.0
            return True, ""

        except Exception as e:
            err_str = str(e)
            logger.error(f"AWS WAF 封禁失败: {ip}: {e}")
            return False, f"AWS WAF 封禁失败: {err_str[:200]}"

    async def unblock_ip(self, ip: str) -> tuple[bool, str]:
        """解封 IP"""
        if not self._has_credentials:
            return False, "AWS 凭证未配置"

        if self.use_waf:
            return await self._unblock_ip_waf(ip)
        return await self._unblock_ip_sg(ip)

    async def _unblock_ip_sg(self, ip: str) -> tuple[bool, str]:
        """通过安全组解封 IP"""
        try:
            import asyncio

            def _do_unblock():
                return self.sg_client.revoke_security_group_ingress(
                    GroupId=self.security_group_id,
                    IpPermissions=[{
                        "IpProtocol": "-1",
                        "FromPort": -1,
                        "ToPort": -1,
                        "IpRanges": [{"CidrIp": f"{ip}/32"}],
                    }],
                )

            resp = await asyncio.to_thread(_do_unblock)
            logger.info(f"AWS 安全组解封成功: ip={ip}, sg={self.security_group_id}")
            self._cached_rules = []
            self._cache_time = 0.0
            return True, ""

        except Exception as e:
            err_str = str(e)
            if "InvalidPermission.NotFound" in err_str:
                return True, "rule not found (already removed)"
            logger.error(f"AWS 安全组解封失败: {ip}: {e}")
            return False, f"AWS 安全组解封失败: {err_str[:200]}"

    async def _unblock_ip_waf(self, ip: str) -> tuple[bool, str]:
        """通过 WAF IP Set 解封 IP"""
        try:
            import asyncio

            def _do_unblock():
                resp = self.waf_client.get_ip_set(
                    Name=self.waf_ip_set_name,
                    Scope="REGIONAL",
                    Id=self.waf_ip_set_id,
                )
                lock_token = resp["LockToken"]
                current_addresses = resp["IPSet"]["Addresses"]

                # 移除 IP
                new_addresses = [a for a in current_addresses if a != f"{ip}/32"]

                if len(new_addresses) == len(current_addresses):
                    return "not_found"

                update_resp = self.waf_client.update_ip_set(
                    Name=self.waf_ip_set_name,
                    Scope="REGIONAL",
                    Id=self.waf_ip_set_id,
                    LockToken=lock_token,
                    Addresses=new_addresses,
                )
                return update_resp["LockToken"]

            result = await asyncio.to_thread(_do_unblock)
            if result == "not_found":
                return True, "rule not found (already removed)"

            logger.info(f"AWS WAF 解封成功: ip={ip}, ip_set={self.waf_ip_set_id}")
            self._cached_rules = []
            self._cache_time = 0.0
            return True, ""

        except Exception as e:
            err_str = str(e)
            logger.error(f"AWS WAF 解封失败: {ip}: {e}")
            return False, f"AWS WAF 解封失败: {err_str[:200]}"

    async def list_rules(self) -> list[dict]:
        """列出所有 SecAgentX 封禁的 IP 规则"""
        if not self._has_credentials:
            return []

        if self.use_waf:
            return await self._list_rules_waf()
        return await self._list_rules_sg()

    async def _list_rules_sg(self) -> list[dict]:
        """通过安全组列出封禁规则"""
        import time as _time
        if self._cached_rules and _time.time() - self._cache_time < 30:
            return self._cached_rules

        try:
            import asyncio

            def _do_list():
                resp = self.sg_client.describe_security_group_rules(
                    Filters=[{"Name": "group-id", "Values": [self.security_group_id]}],
                    MaxResults=100,
                )
                rules = []
                for rule in resp.get("SecurityGroupRules", []):
                    if rule.get("IsEgress", False):
                        continue
                    cidr = rule.get("CidrIpv4", "")
                    desc = (rule.get("Description") or "").lower()
                    if "secagentx" in desc and cidr:
                        rules.append({
                            "ip": cidr.replace("/32", ""),
                            "reason": rule.get("Description", "").replace("SecAgentX: ", ""),
                            "rule_id": rule.get("SecurityGroupRuleId", ""),
                            "protocol": rule.get("IpProtocol", "-1"),
                        })
                return rules

            self._cached_rules = await asyncio.to_thread(_do_list)
            self._cache_time = _time.time()
            return self._cached_rules

        except Exception as e:
            logger.error(f"AWS 安全组查询规则失败: {e}")
            return []

    async def _list_rules_waf(self) -> list[dict]:
        """通过 WAF IP Set 列出封禁 IP"""
        import time as _time
        if self._cached_rules and _time.time() - self._cache_time < 30:
            return self._cached_rules

        try:
            import asyncio

            def _do_list():
                resp = self.waf_client.get_ip_set(
                    Name=self.waf_ip_set_name,
                    Scope="REGIONAL",
                    Id=self.waf_ip_set_id,
                )
                addresses = resp["IPSet"]["Addresses"]
                rules = []
                for addr in addresses:
                    if addr.endswith("/32"):
                        rules.append({
                            "ip": addr.replace("/32", ""),
                            "reason": "WAF IP Set",
                            "source": "waf",
                        })
                return rules

            self._cached_rules = await asyncio.to_thread(_do_list)
            self._cache_time = _time.time()
            return self._cached_rules

        except Exception as e:
            logger.error(f"AWS WAF 查询 IP Set 失败: {e}")
            return []

    async def check_ip(self, ip: str) -> dict:
        """检查指定 IP 是否被封禁"""
        rules = await self.list_rules()
        for r in rules:
            if r["ip"] == ip:
                return {"is_blocked": True, "rule": r}
        return {"is_blocked": False}

    async def health_check(self) -> bool:
        """检查 AWS API 是否可用"""
        if not self._has_credentials:
            return False
        try:
            if self.use_waf:
                _ = await self._list_rules_waf()
            else:
                _ = await self._list_rules_sg()
            return True
        except Exception as e:
            logger.warning(f"AWS 健康检查失败: {e}")
            return False

    async def close(self):
        """关闭客户端连接"""
        self._sg_client = None
        self._waf_client = None
        self._cached_rules = []

