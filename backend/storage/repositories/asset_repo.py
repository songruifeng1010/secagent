"""
资产仓库（AssetRepository）— 风险评分资产维度数据源

仅支持同步 SQLite (Database) 模式；PostgreSQL 场景请直接使用裸 SQL。
查询不可用时不抛异常（返回 None / 空列表），由评分器按"未知"处理。
"""
import uuid
from datetime import datetime, timezone
from typing import Optional
from ..database import Database, Repository


class AssetRepository:
    """资产画像查询/维护。"""

    def __init__(self, db: Database):
        if isinstance(db, Repository):
            raise TypeError(
                "AssetRepository 需要 Database 实例（同步 SQLite），"
                "PostgreSQL 场景请直接使用 repo.fetch_all()"
            )
        self.db = db

    def upsert_asset(self, *, ip: str = "", hostname: str = "",
                     criticality: str = "medium", business_unit: str = "",
                     contains_pii: bool = False, exposed: bool = False,
                     tags: Optional[list] = None) -> str:
        """按 ip 或 hostname 幂等写入资产画像。返回资产 id。"""
        now = datetime.now(timezone.utc).isoformat()
        aid = uuid.uuid4().hex[:12]
        self.db.execute(
            """INSERT OR REPLACE INTO assets
               (id, ip, hostname, criticality, business_unit, contains_pii, exposed, tags, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (aid, ip, hostname, criticality, business_unit,
             int(bool(contains_pii)), int(bool(exposed)),
             __import__("json").dumps(tags or [], ensure_ascii=False), now),
        )
        return aid

    def get_by_ip(self, ip: str) -> Optional[dict]:
        if not ip:
            return None
        row = self.db.fetch_one(
            "SELECT * FROM assets WHERE ip = ? ORDER BY updated_at DESC LIMIT 1", (ip,)
        )
        return self._normalize(row)

    def get_by_hostname(self, hostname: str) -> Optional[dict]:
        if not hostname:
            return None
        row = self.db.fetch_one(
            "SELECT * FROM assets WHERE hostname = ? ORDER BY updated_at DESC LIMIT 1",
            (hostname,),
        )
        return self._normalize(row)

    def resolve(self, *, ip: Optional[str] = None,
                hostname: Optional[str] = None) -> Optional[dict]:
        """按 IP 优先、hostname 兜底解析资产画像。"""
        if ip:
            asset = self.get_by_ip(ip)
            if asset:
                return asset
        if hostname:
            return self.get_by_hostname(hostname)
        return None

    def list_assets(self, limit: int = 100) -> list[dict]:
        rows = self.db.fetch_all(
            "SELECT * FROM assets ORDER BY updated_at DESC LIMIT ?", (limit,)
        )
        return [self._normalize(r) for r in rows]

    @staticmethod
    def _normalize(row) -> Optional[dict]:
        if not row:
            return None
        d = dict(row)
        d["contains_pii"] = bool(d.get("contains_pii"))
        d["exposed"] = bool(d.get("exposed"))
        try:
            d["tags"] = __import__("json").loads(d.get("tags") or "[]")
        except Exception:
            d["tags"] = []
        return d
