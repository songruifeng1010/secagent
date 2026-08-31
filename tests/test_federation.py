"""Federation 模块测试 + AgentRouter 测试 + CircuitBreaker 测试"""

import sys, os, json, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest


# ═══════════════════════ AgentRouter 测试 ═══════════════════════

class TestAgentRouter:
    def test_validate_route_correct(self):
        from backend.orchestrator.agent_router import validate_route
        # 分析师应该处理告警分析
        valid, reason, suggested = validate_route("analyst-001", "分析这个SSH暴力破解告警")
        assert valid, f"分析师应该能处理告警分析: {reason}"
        assert suggested is None

    def test_validate_route_wrong(self):
        from backend.orchestrator.agent_router import validate_route
        # 响应员不应该处理知识查询
        valid, reason, suggested = validate_route("responder-001", "查询MITRE ATT&CK T1566的技术详情")
        assert not valid, f"响应员不应该处理知识查询"
        assert suggested == "knowledge-001", f"应该建议路由到knowledge-001: {suggested}"

    def test_validate_route_intel_for_ip(self):
        from backend.orchestrator.agent_router import validate_route
        valid, reason, suggested = validate_route("intel-001", "查询IP 45.33.32.156的威胁情报")
        assert valid, f"情报员应该能处理IP查询: {reason}"

    def test_validate_route_analyst_for_log(self):
        from backend.orchestrator.agent_router import validate_route
        valid, reason, suggested = validate_route("analyst-001", "分析这批防火墙日志")
        assert valid, f"分析师应该能处理日志分析: {reason}"

    def test_validate_route_knowledge_for_cve(self):
        from backend.orchestrator.agent_router import validate_route
        valid, reason, suggested = validate_route("knowledge-001", "查询CVE-2024-3094漏洞详情")
        assert valid, f"知识库应该能处理CVE查询: {reason}"

    def test_validate_route_empty_task(self):
        from backend.orchestrator.agent_router import validate_route
        valid, reason, suggested = validate_route("analyst-001", "")
        assert not valid, "空任务应该返回无效"
        assert "空" in reason

    def test_validate_route_alert_filter(self):
        from backend.orchestrator.agent_router import validate_route
        valid, reason, suggested = validate_route("alert-filter-001", "批量判断这些告警是否是误报")
        assert valid, f"告警过滤专家应该能处理误报判断: {reason}"


# ═══════════════════════ Federation Core 测试 ═══════════════════════

class TestFederationCore:
    def test_peer_token_init(self):
        """验证对端 Token 初始化"""
        from backend.federation.core import _PEER_TOKENS, _init_peer_tokens
        _PEER_TOKENS.clear()
        config = {"peers": [{"region_id": "beijing", "api_token": "tok-bj"}]}
        _init_peer_tokens(config)
        assert _PEER_TOKENS.get("beijing") == "tok-bj"

    def test_verify_peer_token(self):
        """验证对端 Token 校验"""
        from backend.federation.core import verify_peer_request, _PEER_TOKENS
        _PEER_TOKENS.clear()
        _PEER_TOKENS["shanghai"] = "tok-sh"

        class MockReq:
            def __init__(self, auth, region):
                self.headers = {"authorization": auth, "x-region-id": region}

        import asyncio
        async def test():
            valid, rid = await verify_peer_request(MockReq("Bearer tok-sh", "shanghai"))
            assert valid and rid == "shanghai"
            valid2, _ = await verify_peer_request(MockReq("Bearer wrong", "shanghai"))
            assert not valid2
            valid3, _ = await verify_peer_request(MockReq("", "shanghai"))
            assert not valid3
        asyncio.run(test())

    def test_normalize_timestamp(self):
        """验证时间戳标准化"""
        from backend.federation.core import Federation
        ts1 = Federation._normalize_ts("2026-06-28T10:00:00+00:00")
        ts2 = Federation._normalize_ts("2026-06-28T10:00:00")
        ts3 = Federation._normalize_ts("2026-06-28 10:00:00")
        assert ts1 == ts2 == ts3, f"时间戳应该一致: {ts1} {ts2} {ts3}"
        assert ts1.endswith("Z"), "应统一为Z结尾"
        assert Federation._normalize_ts("") == ""

    def test_utcnow_format(self):
        """验证统一时间戳格式"""
        from backend.federation.core import _utcnow
        ts = _utcnow()
        assert ts.endswith("Z"), f"时间戳应以Z结尾: {ts}"
        assert "T" in ts, f"时间戳应包含T分隔符: {ts}"

    def test_pending_queue_persistence(self):
        """验证待同步队列持久化"""
        from backend.federation.core import _save_pending, _load_pending
        data = {"events": [{"id": "test-1"}], "blacklist": []}
        _save_pending(data)
        loaded = _load_pending()
        assert loaded["events"] == [{"id": "test-1"}]
        # 清理
        import os
        if os.path.exists("data/.federation_pending.json"):
            os.remove("data/.federation_pending.json")

    def test_federation_init_mesh(self):
        """验证 mesh 模式初始化"""
        from backend.federation.core import Federation
        config = {
            "enabled": True, "region_id": "beijing",
            "peers": [{"region_id": "shanghai", "api_url": "http://localhost:8002", "api_token": "tok"}],
        }
        fed = Federation(config)
        assert fed.mode == "mesh"
        assert len(fed._peers) == 1

    def test_federation_init_hub(self):
        """验证 hub 模式初始化"""
        from backend.federation.core import Federation
        config = {
            "enabled": True, "region_id": "hub-center", "mode": "hub",
            "peers": [
                {"region_id": "spoke-a", "api_url": "http://a:8001", "api_token": "tok-a"},
                {"region_id": "spoke-b", "api_url": "http://b:8002", "api_token": "tok-b"},
            ],
        }
        fed = Federation(config)
        assert fed.mode == "hub"
        assert len(fed._peers) == 2

    def test_federation_init_spoke(self):
        """验证 spoke 模式初始化"""
        from backend.federation.core import Federation
        config = {
            "enabled": True, "region_id": "spoke-x", "mode": "spoke",
            "peers": [{"region_id": "hub-center", "api_url": "http://hub:8000", "api_token": "tok"}],
        }
        fed = Federation(config)
        assert fed.mode == "spoke"
        assert len(fed._peers) == 1

    def test_federation_skip_self(self):
        """验证跳过自己的"""
        from backend.federation.core import Federation
        config = {
            "enabled": True, "region_id": "beijing",
            "peers": [
                {"region_id": "shanghai", "api_url": "http://sh:8002", "api_token": "tok"},
                {"region_id": "beijing", "api_url": "http://bj:8001", "api_token": "tok"},  # 自己
            ],
        }
        fed = Federation(config)
        assert len(fed._peers) == 1, "应该跳过自己"


# ═══════════════════════ Circuit Breaker 测试 ═══════════════════════

class TestCircuitBreaker:
    def test_callback_wired(self):
        """验证熔断器回调可以被设置"""
        from backend.security.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker()
        calls = []
        async def mock_cb(msg):
            calls.append(msg)
        cb.set_escalate_callback(mock_cb)
        assert cb._escalate_callback is not None

    def test_record_failure_triggers_callback(self):
        """验证自动恢复失败时回调被触发"""
        from backend.security.circuit_breaker import CircuitBreaker, MAX_CONSECUTIVE_FAILURES as MCF
        cb = CircuitBreaker()
        # 强制进入 HALF_OPEN 状态
        cb._state = cb.STATE_HALF_OPEN
        cb._failures = MCF - 1  # 差一次就触发

        calls = []
        async def mock_cb(msg):
            calls.append(msg)

        cb.set_escalate_callback(mock_cb)
        import asyncio
        asyncio.run(cb.record_failure())
        assert cb._state == cb.STATE_OPEN, "应进入 OPEN 状态"
        assert len(calls) == 1, "回调应被触发"
        assert "熔断器自动恢复失败" in calls[0], f"回调消息应包含失败信息: {calls[0]}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
