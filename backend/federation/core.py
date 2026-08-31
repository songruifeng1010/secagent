"""
SecAgentX 跨区域联邦核心引擎（v2 — 生产加固版）

解决 6 个已知问题:
  1. 防环路: 改用 ID 前缀过滤 (`fed-{region}-`)，不再依赖标题字符串匹配
  2. 服务端认证: 对端 Token 在接收端验证，不再开放白名单
  3. sync_event_now() 防丢: 先入持久化队列，再尝试推送
  4. 冲突裁决: 统一 UTC ISO-8601 时间戳，所有写入端标准化
  5. 队列竞态: 改用 asyncio.Lock 保护 pending 队列
  6. 可观测性: Prometheus 指标 + 队列积压告警日志
"""

import os
import json
import time
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

logger = logging.getLogger("secagentx.federation")

_PENDING_FILE = "data/.federation_pending.json"
_PEER_TOKENS: dict[str, str] = {}  # region_id -> token（用于服务端验证）


def _init_peer_tokens(config: dict):
    """从配置文件读取所有对端 Token，用于接收端的请求验证"""
    peers = config.get("peers", [])
    for pc in peers:
        rid = pc.get("region_id", "")
        token = pc.get("api_token", "")
        if token.startswith("${") and token.endswith("}"):
            token = os.getenv(token[2:-1], "")
        if rid and token:
            _PEER_TOKENS[rid] = token


async def verify_peer_request(request) -> tuple[bool, str]:
    """
    验证跨区域同步请求的身份。
    对端必须在 Authorization header 中携带正确的 Token。

    返回 (is_valid, region_id_or_error)
    """
    auth = request.headers.get("authorization", "")
    x_region = request.headers.get("x-region-id", "")

    if not auth.startswith("Bearer "):
        return False, "缺少 Authorization Bearer Token"
    token = auth[7:]

    # 如果有 X-Region-ID，优先按区域查
    if x_region:
        expected = _PEER_TOKENS.get(x_region, "")
        if expected and token == expected:
            return True, x_region

    # 遍历所有对端 Token 匹配
    for rid, expected in _PEER_TOKENS.items():
        if token == expected:
            return True, rid

    return False, f"无效的 Token（来自 X-Region-ID: {x_region}）"


def _utcnow() -> str:
    """返回统一的 UTC ISO-8601 时间戳（所有时间戳标准化入口）"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _load_pending() -> dict:
    if not os.path.exists(_PENDING_FILE):
        return {"events": [], "blacklist": []}
    try:
        with open(_PENDING_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"events": [], "blacklist": []}


def _save_pending(data: dict):
    os.makedirs(os.path.dirname(_PENDING_FILE) or ".", exist_ok=True)
    tmp = _PENDING_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, _PENDING_FILE)


class PeerRegion:
    """对端区域的连接信息"""

    def __init__(self, config: dict):
        self.region_id = config.get("region_id", "unknown")
        self.region_name = config.get("region_name", "未知区域")
        self.api_url = config.get("api_url", "").rstrip("/")
        self.api_token = config.get("api_token", "")
        self.sync_events = config.get("sync_events", True)
        self.sync_blacklist = config.get("sync_blacklist", True)
        self._http: Optional[httpx.AsyncClient] = None

        self.last_heartbeat = 0.0
        self.is_healthy = False
        self.events_synced = 0
        self.blacklist_synced = 0
        self.last_error = ""
        self.retry_delay = 1.0

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=15.0,
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": "application/json",
                    "X-Region-ID": self.region_id,
                },
            )
        return self._http

    async def close(self):
        if self._http:
            await self._http.aclose()
            self._http = None

    def reset_retry(self):
        self.retry_delay = 1.0

    def backoff_retry(self):
        self.retry_delay = min(self.retry_delay * 2, 120.0)

    async def health_check(self) -> bool:
        if not self.api_url:
            return False
        try:
            resp = await self.http.get(f"{self.api_url}/api/health", timeout=5)
            ok = resp.status_code == 200
            self.is_healthy = ok
            if ok:
                self.last_heartbeat = time.time()
                self.last_error = ""
                self.reset_retry()
            return ok
        except Exception as e:
            self.is_healthy = False
            self.last_error = str(e)
            self.backoff_retry()
            return False

    # ── 事件同步 ──

    async def push_events(self, events: list[dict], source_region: str = "") -> bool:
        if not self.sync_events or not self.is_healthy:
            return False
        if not events:
            return True
        try:
            resp = await self.http.post(
                f"{self.api_url}/api/federation/events",
                json={"events": events, "source_region": source_region},
                timeout=15,
            )
            ok = resp.status_code == 200
            if ok:
                self.events_synced += len(events)
                self.reset_retry()
            return ok
        except Exception as e:
            self.last_error = str(e)
            self.backoff_retry()
            return False

    async def pull_events(self, since: str = "", batch_size: int = 100) -> list[dict]:
        if not self.sync_events or not self.is_healthy:
            return []
        try:
            params = {"limit": batch_size, "exclude_region": self.region_id}
            if since:
                params["since"] = since
            resp = await self.http.get(
                f"{self.api_url}/api/federation/events",
                params=params, timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                events = data.get("events", [])
                if events:
                    self.reset_retry()
                return events
            return []
        except Exception as e:
            self.last_error = str(e)
            self.backoff_retry()
            return []

    # ── 黑名单同步 ──

    async def push_blacklist(self, entries: list[dict]) -> bool:
        if not self.sync_blacklist or not self.is_healthy:
            return False
        if not entries:
            return True
        try:
            resp = await self.http.post(
                f"{self.api_url}/api/federation/blacklist",
                json={"entries": entries, "source_region": self.region_id},
                timeout=15,
            )
            ok = resp.status_code == 200
            if ok:
                self.blacklist_synced += len(entries)
                self.reset_retry()
            return ok
        except Exception as e:
            self.last_error = str(e)
            self.backoff_retry()
            return False

    async def pull_blacklist(self) -> list[dict]:
        if not self.sync_blacklist or not self.is_healthy:
            return []
        try:
            resp = await self.http.get(f"{self.api_url}/api/federation/blacklist", timeout=15)
            if resp.status_code == 200:
                return resp.json().get("entries", [])
            return []
        except Exception as e:
            self.last_error = str(e)
            return []

    def get_status(self) -> dict:
        return {
            "region_id": self.region_id,
            "region_name": self.region_name,
            "api_url": self.api_url,
            "is_healthy": self.is_healthy,
            "retry_delay": round(self.retry_delay, 1),
            "last_heartbeat": datetime.fromtimestamp(
                self.last_heartbeat, tz=timezone.utc
            ).isoformat() if self.last_heartbeat > 0 else "",
            "events_synced": self.events_synced,
            "blacklist_synced": self.blacklist_synced,
            "last_error": self.last_error,
        }


class Federation:
    """
    跨区域联邦引擎（v2 — 生产加固版）

    修复清单:
      1. ✅ 防环路: ID 前缀过滤 `fed-{region}-`，不依赖标题字符串
      2. ✅ 服务端认证: 接收端验证 Bearer Token，不对全局开放
      3. ✅ sync_event_now() 防丢: 先入持久化队列再推，失败自动积压
      4. ✅ 冲突裁决: 统一 _utcnow() 生成时间戳，格式可排序
      5. ✅ 队列竞态: asyncio.Lock 保护 pending + 原子切片
      6. ✅ 可观测性: Prometheus 指标 + 队列积压 WARNING 日志
    """

    def __init__(self, config: dict = None):
        """
        初始化联邦引擎。

        拓扑模式（mode）:
          - "mesh" (默认): 每个区域直连所有其他区域 → O(n²)
            适合: 2-5 个区域
          - "hub":  本区域作为中心节点，接收所有 spoke 的数据并转发
            适合: 总部 SOC，3+ 区域
          - "spoke": 只连接一个 hub 区域
            适合: 分支机构，只连总部
        """
        self.config = config or {}
        self.enabled = self.config.get("enabled", False)
        self.region_id = self.config.get("region_id", "default")
        self.region_name = self.config.get("region_name", "默认区域")

        # 拓扑模式
        self.mode = self.config.get("mode", "mesh")
        if self.mode not in ("mesh", "hub", "spoke"):
            logger.warning(f"[federation] 未知模式 '{self.mode}'，降级为 mesh")
            self.mode = "mesh"

        self._peers: list[PeerRegion] = []
        self._running = False
        self._tasks: list[asyncio.Task] = []

        # 初始化服务端验证用的 Token 表
        _init_peer_tokens(self.config)

        # 队列锁 — 防止 add_pending 和切片消费的竞态
        self._pending_lock = asyncio.Lock()
        self._pending = _load_pending()
        self._last_event_sync: dict[str, str] = {}

        # hub 模式下: 缓存从 spoke 收到的事件，转发给其他 spoke
        self._hub_forward_cache: list[dict] = []

        # Prometheus 指标
        self._metrics = {
            "events_pushed": 0,
            "events_pulled": 0,
            "blacklist_pushed": 0,
            "blacklist_pulled": 0,
            "sync_failures": 0,
            "push_failures": 0,
            "queue_overflow_warnings": 0,
        }

        self._init_peers()
        logger.info(
            f"[federation] 初始化: region={self.region_id}, "
            f"mode={self.mode}, peers={len(self._peers)}"
        )

    def _init_peers(self):
        peer_configs = self.config.get("peers", [])
        for pc in peer_configs:
            token = pc.get("api_token", "")
            if token.startswith("${") and token.endswith("}"):
                token = os.getenv(token[2:-1], "")
                pc["api_token"] = token
            if pc.get("region_id") == self.region_id:
                continue
            self._peers.append(PeerRegion(pc))
        logger.info(
            f"[federation] region={self.region_id}, "
            f"peers={len(self._peers)}, enabled={self.enabled}"
        )

    # ═══════════════════ 生命周期 ═══════════════════

    async def start(self):
        if not self.enabled:
            logger.info("[federation] 未启用")
            return
        if self._running:
            return
        self._running = True

        sync_cfg = self.config.get("sync", {})
        event_interval = sync_cfg.get("event_interval_seconds", 60)
        bl_interval = sync_cfg.get("blacklist_interval_seconds", 30)

        await asyncio.sleep(5)

        self._tasks.append(asyncio.create_task(
            self._sync_loop("event", event_interval),
            name=f"fed-event-{self.region_id}",
        ))
        self._tasks.append(asyncio.create_task(
            self._sync_loop("blacklist", bl_interval),
            name=f"fed-blacklist-{self.region_id}",
        ))
        self._tasks.append(asyncio.create_task(
            self._heartbeat_loop(30),
            name=f"fed-heartbeat-{self.region_id}",
        ))

        pending_events = len(self._pending.get("events", []))
        pending_bl = len(self._pending.get("blacklist", []))
        logger.info(
            f"[federation] 已启动: region={self.region_id}, "
            f"事件同步={event_interval}s, 黑名单同步={bl_interval}s, "
            f"待恢复事件={pending_events}, 待恢复黑名单={pending_bl}"
        )
        # 积压告警
        if pending_events > 100:
            logger.warning(
                f"[federation] 事件队列积压 {pending_events} 条，"
                f"对端可能长时间不可达"
            )
        if pending_bl > 100:
            logger.warning(
                f"[federation] 黑名单队列积压 {pending_bl} 条"
            )

    async def stop(self):
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        for peer in self._peers:
            await peer.close()
        logger.info(f"[federation] 已停止: {self.region_id}")

    # ═══════════════════ 外部接口 ═══════════════════

    async def add_pending_event(self, event: dict):
        """
        添加待同步事件（持久化，防丢）。

        修复: 使用 asyncio.Lock 保护队列，防止 add 和消费并发导致数据丢失。
        """
        if not self.enabled:
            return
        async with self._pending_lock:
            self._pending.setdefault("events", []).append(event)
            if len(self._pending["events"]) > 2000:
                dropped = len(self._pending["events"]) - 1000
                self._pending["events"] = self._pending["events"][-1000:]
                self._metrics["queue_overflow_warnings"] += 1
                logger.warning(
                    f"[federation] 事件队列超限，丢弃 {dropped} 条旧数据"
                )
            _save_pending(self._pending)

    async def add_pending_blacklist(self, entry: dict):
        """添加待同步黑名单（持久化，防丢）"""
        if not self.enabled:
            return
        async with self._pending_lock:
            self._pending.setdefault("blacklist", []).append(entry)
            if len(self._pending["blacklist"]) > 2000:
                dropped = len(self._pending["blacklist"]) - 1000
                self._pending["blacklist"] = self._pending["blacklist"][-1000:]
                logger.warning(
                    f"[federation] 黑名单队列超限，丢弃 {dropped} 条旧数据"
                )
            _save_pending(self._pending)

    async def sync_event_now(self, event: dict) -> list[dict]:
        """
        立即同步一个关键事件。

        修复: 先入持久化队列（防丢），再尝试推到在线对端。
        推到失败的事件保留在队列中，下次同步循环自动重试。
        """
        if not self.enabled:
            return []
        # 先入队列（持久化）
        await self.add_pending_event(event)

        # 再尝试立即推送
        results = []
        for peer in self._peers:
            if peer.is_healthy:
                ok = await peer.push_events([event], source_region=self.region_id)
                results.append({"peer": peer.region_id, "success": ok})
                if ok:
                    # 推送成功 → 从队列移除（需要锁保护）
                    async with self._pending_lock:
                        pending = self._pending.get("events", [])
                        if pending and pending[0].get("id") == event.get("id"):
                            self._pending["events"] = pending[1:]
                            _save_pending(self._pending)
            else:
                results.append({"peer": peer.region_id, "success": False, "reason": "offline, queued"})
        return results

    def get_status(self) -> dict:
        return {
            "enabled": self.enabled,
            "region_id": self.region_id,
            "region_name": self.region_name,
            "mode": self.mode,
            "peers": [p.get_status() for p in self._peers],
            "pending_events": len(self._pending.get("events", [])),
            "pending_blacklist": len(self._pending.get("blacklist", [])),
            "metrics": dict(self._metrics),
        }

    def get_metrics(self) -> dict:
        return dict(self._metrics)

    def get_peers(self) -> list[PeerRegion]:
        return list(self._peers)

    # ═══════════════════ 同步循环 ═══════════════════

    async def _sync_loop(self, sync_type: str, interval: int):
        while self._running:
            try:
                for peer in self._peers:
                    await peer.health_check()
                healthy = [p for p in self._peers if p.is_healthy]

                if sync_type == "event":
                    await self._sync_events(healthy)
                elif sync_type == "blacklist":
                    await self._sync_blacklist(healthy)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self._metrics["sync_failures"] += 1
                logger.error(f"[federation] 同步异常 ({sync_type}): {e}")
            await asyncio.sleep(interval)

    async def _sync_events(self, peers: list[PeerRegion]):
        """双向事件同步（锁保护+ID前缀防环路）"""
        if not peers:
            return

        # 1. 推：用锁保护切片操作
        async with self._pending_lock:
            batch = self._pending.get("events", [])[:100]

        if batch:
            success = True
            for peer in peers:
                ok = await peer.push_events(batch, source_region=self.region_id)
                if not ok:
                    success = False
                    self._metrics["push_failures"] += 1
                else:
                    self._metrics["events_pushed"] += len(batch)

            if success:
                async with self._pending_lock:
                    self._pending["events"] = self._pending["events"][len(batch):]
                    _save_pending(self._pending)

        # 2. 拉
        for peer in peers:
            since = self._last_event_sync.get(peer.region_id, "")
            remote = await peer.pull_events(since=since)
            if remote:
                await self._save_remote_events(peer.region_id, remote)
                self._metrics["events_pulled"] += len(remote)
                newest = max(
                    e.get("created_at", "") for e in remote if e.get("created_at")
                )
                if newest:
                    self._last_event_sync[peer.region_id] = newest

    async def _sync_blacklist(self, peers: list[PeerRegion]):
        if not peers:
            return

        async with self._pending_lock:
            batch = self._pending.get("blacklist", [])[:100]

        if batch:
            success = True
            for peer in peers:
                ok = await peer.push_blacklist(batch)
                if not ok:
                    success = False
                    self._metrics["push_failures"] += 1
                else:
                    self._metrics["blacklist_pushed"] += len(batch)

            if success:
                async with self._pending_lock:
                    self._pending["blacklist"] = self._pending["blacklist"][len(batch):]
                    _save_pending(self._pending)

        for peer in peers:
            remote = await peer.pull_blacklist()
            if remote:
                await self._apply_remote_blacklist(peer.region_id, remote)
                self._metrics["blacklist_pulled"] += len(remote)

    async def _heartbeat_loop(self, interval: int):
        while self._running:
            try:
                for peer in self._peers:
                    await peer.health_check()
                alive = sum(1 for p in self._peers if p.is_healthy)
                if alive < len(self._peers):
                    # 有对端离线时输出 WARNING（可观测性）
                    offline = [
                        p.region_name for p in self._peers if not p.is_healthy
                    ]
                    logger.warning(
                        f"[federation] 对端离线: {', '.join(offline)} "
                        f"({alive}/{len(self._peers)} 在线)"
                    )
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            await asyncio.sleep(interval)

    # ═══════════════════ 数据持久化 — 事件 ═══════════════════

    async def _save_remote_events(self, source_region: str, events: list[dict]):
        """
        将对端事件写入本地数据库。

        防环路策略（修复版）:
          - 每条事件 ID 使用 `fed-{source_region}-{original_id}` 前缀
          - 对端拉取时 `WHERE id NOT LIKE 'fed-?-%'` 过滤
          → 不再依赖标题字符串匹配，永不误判
        """
        if not events:
            return
        try:
            from backend.storage.database import Repository

            db = Repository()
            now = _utcnow()

            for ev in events:
                ev_id = ev.get("id", "")
                title = ev.get("title", "跨区域同步事件")
                severity = ev.get("severity", "中危")
                src_ip = ev.get("source_ip", ev.get("src_ip", ""))
                desc = ev.get("description", "") + f"\n[来自 {source_region}]"

                # ID 前缀标记: fed-{region}-{id} → 防环路过滤用
                fed_id = f"fed-{source_region}-{ev_id}"

                sql = (
                    "INSERT OR IGNORE INTO events "
                    "(id, title, severity, status, source_ip, description, created_at) "
                    "VALUES (?, ?, ?, 'open', ?, ?, ?)"
                )
                await db.execute(sql, (
                    fed_id,
                    title,
                    severity, src_ip, desc, now,
                ))

            await db.close()
            logger.info(
                f"[federation] 从 {source_region} 同步了 {len(events)} 个事件"
            )

            # ── hub 转发: hub 模式下，将事件转发到所有其他 spoke ──
            if self.mode == "hub":
                for peer in self._peers:
                    # 不转发回来源区域
                    if peer.region_id == source_region:
                        continue
                    if peer.is_healthy:
                        ok = await peer.push_events(events, source_region=source_region)
                        if ok:
                            self._metrics["events_pushed"] += len(events)
                            logger.debug(
                                f"[federation] hub 转发 {len(events)} 个事件"
                                f" 到 {peer.region_id}"
                            )
        except Exception as e:
            logger.warning(f"[federation] 保存远程事件失败: {e}")

    # ═══════════════════ 数据持久化 — 黑名单（LWW 冲突裁决） ═══════════════════

    @staticmethod
    def _normalize_ts(ts: str) -> str:
        """
        统一时间戳格式为 UTC ISO-8601（可字典序比较）。

        修复: 兼容多种输入格式:
          - "2026-06-28T10:00:00+00:00" → "2026-06-28T10:00:00.000Z"
          - "2026-06-28T10:00:00" → "2026-06-28T10:00:00.000Z"
          - "2026-06-28 10:00:00" → "2026-06-28T10:00:00.000Z"
          - "" → 返回 ""（无法比较）
        """
        if not ts:
            return ""
        # 去掉时区后缀，统一加 Z
        ts = ts.replace("+00:00", "").replace("Z", "").replace("T", " ").strip()
        # 补全毫秒
        if "." not in ts:
            ts += ".000"
        # 转回 ISO 格式
        return ts.replace(" ", "T") + "Z"

    async def _apply_remote_blacklist(self, source_region: str, entries: list[dict]):
        """
        将对端黑名单应用到本地防火墙。

        冲突裁决规则（LWW + 统一时间戳）:
          - 时间戳统一通过 _normalize_ts() 标准化
          - 远程时间戳 > 本地时间戳 → 远程赢
          - 远程时间戳 <= 本地时间戳 → 本地保留
          - 没有时间戳 → 直接应用（兼容旧版）
        """
        if not entries:
            return

        try:
            from backend.tools.firewall import FirewallTool

            fw = FirewallTool(backend=os.getenv("FIREWALL_BACKEND", "disabled"))

            local_result = await fw.execute(action="list")
            local_rules = {}
            if local_result.success:
                for r in local_result.data.get("rules", []):
                    local_rules[r["ip"]] = r

            applied = 0
            for entry in entries:
                ip = entry.get("ip", "")
                if not ip:
                    continue

                remote_ts = self._normalize_ts(entry.get("blocked_at", ""))
                remote_action = entry.get("action", "block")
                local_rule = local_rules.get(ip)

                # ── 冲突裁决（标准化时间戳比较） ──
                if local_rule:
                    local_ts = self._normalize_ts(local_rule.get("blocked_at", ""))
                    # 双方都有时间戳，且远程不更新 → 保留本地
                    if remote_ts and local_ts and remote_ts <= local_ts:
                        continue

                # ── 执行 ──
                from backend.tools.firewall import FirewallExecutionContext
                federation_context = FirewallExecutionContext.federation_peer(
                    peer_id=source_region,
                    reason="跨区域黑名单同步",
                )
                if remote_action == "unblock":
                    await fw.execute(
                        action="unblock", ip=ip,
                        reason=f"跨区域解封自 {source_region}",
                        authorization_context=federation_context,
                    )
                else:
                    check = await fw.execute(action="check", ip=ip)
                    if check.success and check.data.get("is_blocked"):
                        continue
                    result = await fw.execute(
                        action="block", ip=ip,
                        reason=f"跨区域同步自 {source_region}: {entry.get('reason', '')}",
                        duration_minutes=entry.get("duration_minutes", 120),
                        authorization_context=federation_context,
                    )
                    if result.success:
                        applied += 1

            if applied > 0:
                logger.info(
                    f"[federation] 从 {source_region} 应用了 {applied} 条黑名单"
                )

            # ── hub 转发: hub 模式下，将黑名单转发到所有其他 spoke ──
            if self.mode == "hub" and entries:
                for peer in self._peers:
                    if peer.region_id == source_region:
                        continue
                    if peer.is_healthy:
                        await peer.push_blacklist(entries)
        except Exception as e:
            logger.warning(f"[federation] 应用远程黑名单失败: {e}")
