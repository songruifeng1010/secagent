"""
SecAgentX 跨区域联邦层

提供三个核心能力:
  1. 跨区域事件同步 — 本区域的告警/事件自动推送到其他区域
  2. 跨区域黑名单同步 — 一个区域封禁的 IP 自动同步到所有区域
  3. 区域注册表 — 维护所有区域的健康状态和元数据

使用方式:
    from backend.federation import Federation
    fed = Federation(config)
    await fed.start()  # 启动所有同步协程

    # 对端 API 验证（在 api_server.py 中使用）
    from backend.federation import verify_peer_request
    valid, region_id = await verify_peer_request(request)
"""

from .core import Federation, verify_peer_request

__all__ = ["Federation", "verify_peer_request"]

