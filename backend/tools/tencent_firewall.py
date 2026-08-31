"""
腾讯云安全组防火墙适配器

通过腾讯云 SDK 管理安全组规则，实现 IP 封禁/解封。

环境变量:
  TENCENT_SECRET_ID       — 腾讯云 SecretId
  TENCENT_SECRET_KEY      — 腾讯云 SecretKey
  TENCENT_SECURITY_GROUP_ID — 安全组 ID（必填）
  TENCENT_REGION_ID       — 区域（默认 ap-guangzhou）
  TENCENT_VPC_ID          — VPC ID（可选，跨 VPC 场景）

注意:
  - 需要对安全组有 "ModifySecurityGroupPolicys" 权限
  - 建议使用子账号，授予最小权限
  - API 端点默认为内网接入
"""

import os
import json
import time
import logging
from datetime import datetime, timezone
from typing import Optional
from .base import FirewallAdapter

logger = logging.getLogger("secagentx.firewall.tencent")


class TencentFirewallAdapter(FirewallAdapter):
    """
    腾讯云安全组防火墙后端

    通过安全组的入站规则实现 IP 封禁。
    腾讯云安全组规则通过单个 API 全量替换的方式管理。

    如何获取安全组 ID:
      1. 登录腾讯云控制台 → VPC → 安全组
      2. 找到目标安全组，复制 ID（如 sg-xxxxxxxx）
      3. 配置在 .env: TENCENT_SECURITY_GROUP_ID=sg-xxxxxxxx
    """

    def __init__(self):
        self.secret_id = os.getenv("TENCENT_SECRET_ID", "")
        self.secret_key = os.getenv("TENCENT_SECRET_KEY", "")
        self.security_group_id = os.getenv("TENCENT_SECURITY_GROUP_ID", "")
        self.region_id = os.getenv("TENCENT_REGION_ID", "ap-guangzhou")
        self.vpc_id = os.getenv("TENCENT_VPC_ID", "")

        self._client = None
        self._has_credentials = bool(
            self.secret_id and self.secret_key and self.security_group_id
        )
        # 缓存
        self._cached_rules: list[dict] = []
        self._cache_time = 0.0

    @property
    def client(self):
        """延迟初始化腾讯云 VPC Client"""
        if self._client is None and self._has_credentials:
            try:
                from tencentcloud.common import credential
                from tencentcloud.common.profile.client_profile import ClientProfile
                from tencentcloud.common.profile.http_profile import HttpProfile
                from tencentcloud.vpc.v20170312 import vpc_client, models

                cred = credential.Credential(self.secret_id, self.secret_key)
                httpProfile = HttpProfile()
                httpProfile.endpoint = f"vpc.tencentcloudapi.com"
                clientProfile = ClientProfile()
                clientProfile.httpProfile = httpProfile
                self._client = vpc_client.VpcClient(cred, self.region_id, clientProfile)

            except ImportError:
                logger.critical(
                    "腾讯云 SDK 未安装。请执行: pip install tencentcloud-sdk-python-vpc"
                )
                raise
            except Exception as e:
                logger.error(f"腾讯云客户端初始化失败: {e}")
                raise
        return self._client

    async def block_ip(self, ip: str, reason: str = "",
                        duration_minutes: int = 120) -> tuple[bool, str]:
        """封禁 IP：在安全组入方向添加拒绝规则"""
        if not self._has_credentials:
            return False, "腾讯云凭证未配置（TENCENT_SECRET_ID / KEY）"

        try:
            from tencentcloud.vpc.v20170312 import models
            import asyncio

            def _do_block():
                req = models.ModifySecurityGroupPolicysRequest()
                req.SecurityGroupId = self.security_group_id

                # 获取现有入站规则
                old_req = models.DescribeSecurityGroupPolicysRequest()
                old_req.SecurityGroupId = self.security_group_id
                old_resp = self.client.DescribeSecurityGroupPolicys(old_req)

                ingress_policies = []
                if old_resp.SecurityGroupPolicySet and old_resp.SecurityGroupPolicySet.Ingress:
                    ingress_policies = [
                        self._policy_to_dict(p) for p in old_resp.SecurityGroupPolicySet.Ingress
                    ]

                # 添加新的拒绝规则（插在最前面，优先级最高）
                new_policy = self._policy_to_dict(None)
                new_policy["PolicyIndex"] = 0
                new_policy["Protocol"] = "ALL"
                new_policy["Port"] = "ALL"
                new_policy["CidrBlock"] = f"{ip}/32"
                new_policy["Action"] = "DROP"
                new_policy["PolicyDescription"] = f"SecAgentX: {reason[:120]}" if reason else "SecAgentX: auto-block"

                # 插入规则并重排索引
                new_policies = [new_policy] + ingress_policies
                for i, p in enumerate(new_policies):
                    p["PolicyIndex"] = i

                req.IngressPolicySet = self._policies_to_model(new_policies)
                req.EgressPolicySet = []

                resp = self.client.ModifySecurityGroupPolicys(req)
                return resp.RequestId

            request_id = await asyncio.to_thread(_do_block)
            logger.info(f"腾讯云封禁成功: ip={ip}, sg={self.security_group_id}, request_id={request_id}")
            self._cached_rules = []
            self._cache_time = 0.0
            return True, ""

        except Exception as e:
            err_str = str(e)
            if "InvalidSecurityGroupID.NotFound" in err_str:
                return False, f"安全组不存在: {self.security_group_id}"
            logger.error(f"腾讯云封禁失败: {ip}: {e}")
            return False, f"腾讯云封禁失败: {err_str[:200]}"

    async def unblock_ip(self, ip: str) -> tuple[bool, str]:
        """解封 IP：从安全组入方向删除规则"""
        if not self._has_credentials:
            return False, "腾讯云凭证未配置"

        try:
            from tencentcloud.vpc.v20170312 import models
            import asyncio

            def _do_unblock():
                req = models.ModifySecurityGroupPolicysRequest()
                req.SecurityGroupId = self.security_group_id

                # 获取现有入站规则，过滤掉要解封的 IP
                old_req = models.DescribeSecurityGroupPolicysRequest()
                old_req.SecurityGroupId = self.security_group_id
                old_resp = self.client.DescribeSecurityGroupPolicys(old_req)

                ingress_policies = []
                removed = False
                if old_resp.SecurityGroupPolicySet and old_resp.SecurityGroupPolicySet.Ingress:
                    for p in old_resp.SecurityGroupPolicySet.Ingress:
                        p_dict = self._policy_to_dict(p)
                        cidr = p_dict.get("CidrBlock", "")
                        if cidr == f"{ip}/32" and p_dict.get("Action") == "DROP":
                            removed = True
                            continue
                        ingress_policies.append(p_dict)

                if not removed:
                    return "not_found"

                for i, p in enumerate(ingress_policies):
                    p["PolicyIndex"] = i

                req.IngressPolicySet = self._policies_to_model(ingress_policies)
                req.EgressPolicySet = []

                resp = self.client.ModifySecurityGroupPolicys(req)
                return resp.RequestId

            result = await asyncio.to_thread(_do_unblock)
            if result == "not_found":
                return True, "rule not found (already removed)"

            logger.info(f"腾讯云解封成功: ip={ip}, sg={self.security_group_id}, request_id={result}")
            self._cached_rules = []
            self._cache_time = 0.0
            return True, ""

        except Exception as e:
            err_str = str(e)
            logger.error(f"腾讯云解封失败: {ip}: {e}")
            return False, f"腾讯云解封失败: {err_str[:200]}"

    async def list_rules(self) -> list[dict]:
        """列出所有 SecAgentX 封禁的 IP 规则"""
        if not self._has_credentials:
            return []

        import time as _time
        if self._cached_rules and _time.time() - self._cache_time < 30:
            return self._cached_rules

        try:
            from tencentcloud.vpc.v20170312 import models
            import asyncio

            def _do_list():
                req = models.DescribeSecurityGroupPolicysRequest()
                req.SecurityGroupId = self.security_group_id
                resp = self.client.DescribeSecurityGroupPolicys(req)

                rules = []
                if resp.SecurityGroupPolicySet and resp.SecurityGroupPolicySet.Ingress:
                    for p in resp.SecurityGroupPolicySet.Ingress:
                        desc = (p.PolicyDescription or "").lower()
                        if "secagentx" in desc and p.Action == "DROP":
                            rules.append({
                                "ip": p.CidrBlock.replace("/32", ""),
                                "reason": p.PolicyDescription.replace("SecAgentX: ", ""),
                                "action": p.Action,
                                "protocol": p.Protocol,
                                "port": p.Port,
                                "policy_index": p.PolicyIndex,
                            })
                return rules

            self._cached_rules = await asyncio.to_thread(_do_list)
            self._cache_time = _time.time()
            return self._cached_rules

        except Exception as e:
            logger.error(f"腾讯云查询规则失败: {e}")
            return []

    async def check_ip(self, ip: str) -> dict:
        """检查指定 IP 是否被封禁"""
        rules = await self.list_rules()
        for r in rules:
            if r["ip"] == ip:
                return {"is_blocked": True, "rule": r}
        return {"is_blocked": False}

    async def health_check(self) -> bool:
        """检查腾讯云 API 是否可用"""
        if not self._has_credentials:
            return False
        try:
            rules = await self.list_rules()
            return True
        except Exception as e:
            logger.warning(f"腾讯云健康检查失败: {e}")
            return False

    async def close(self):
        """关闭客户端连接"""
        self._client = None
        self._cached_rules = []

    # ─── 腾讯云 SDK 模型转换辅助方法 ───

    def _policy_to_dict(self, policy) -> dict:
        """将 SDK Policy 对象转为字典"""
        if policy is None:
            return {
                "PolicyIndex": 0,
                "Protocol": "ALL",
                "Port": "ALL",
                "CidrBlock": "",
                "Action": "DROP",
                "PolicyDescription": "",
            }
        return {
            "PolicyIndex": policy.PolicyIndex,
            "Protocol": policy.Protocol,
            "Port": policy.Port,
            "CidrBlock": policy.CidrBlock,
            "Action": policy.Action,
            "PolicyDescription": policy.PolicyDescription or "",
        }

    def _policies_to_model(self, policies: list[dict]):
        """将字典列表转为 SDK 模型对象列表"""
        from tencentcloud.vpc.v20170312 import models as tc_models

        result = []
        for p in policies:
            m = tc_models.SecurityGroupPolicy()
            m.PolicyIndex = p.get("PolicyIndex", 0)
            m.Protocol = p.get("Protocol", "ALL")
            m.Port = p.get("Port", "ALL")
            m.CidrBlock = p.get("CidrBlock", "")
            m.Action = p.get("Action", "DROP")
            m.PolicyDescription = p.get("PolicyDescription", "")
            result.append(m)
        return result

