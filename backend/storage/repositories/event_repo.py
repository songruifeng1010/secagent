import uuid
from datetime import datetime, timezone
from typing import Optional, Any
from ..database import Database, Repository


class EventRepository:
    """
    事件仓库 — 仅支持 SQLite (Database)

    注意：PostgreSQL 场景请直接使用 Repository + 裸 SQL。
    此类在异步 Repository 模式下不可用，后续版本将统一。
    """

    def __init__(self, db: Database):
        if isinstance(db, Repository):
            raise TypeError(
                "EventRepository 需要 Database 实例（同步 SQLite），"
                "PostgreSQL 场景请直接使用 repo.fetch_all()"
            )
        self.db = db

    def create_event(self, title: str, severity: str = "低危",
                     source_ip: str = "", alert_type: str = "",
                     mitre_tactic_id: str = "", mitre_technique_id: str = "",
                     description: str = "") -> str:
        eid = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        self.db.insert(
            """INSERT INTO events (id, title, severity, status, source_ip, alert_type,
               mitre_tactic_id, mitre_technique_id, description, created_at)
               VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)""",
            (eid, title, severity, source_ip, alert_type,
             mitre_tactic_id, mitre_technique_id, description, now),
        )
        return eid

    def resolve_event(self, event_id: str, resolution: str, resolved_by: str = ""):
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute(
            "UPDATE events SET status = 'resolved', resolution = ?, resolved_by = ?, resolved_at = ? WHERE id = ?",
            (resolution, resolved_by, now, event_id),
        )

    def get_open_events(self, severity: Optional[str] = None) -> list[dict]:
        if severity:
            return self.db.fetch_all(
                "SELECT * FROM events WHERE status = 'open' AND severity = ? ORDER BY created_at DESC",
                (severity,),
            )
        return self.db.fetch_all(
            "SELECT * FROM events WHERE status = 'open' ORDER BY created_at DESC"
        )

    def get_events_by_ip(self, ip: str, limit: int = 20) -> list[dict]:
        return self.db.fetch_all(
            "SELECT * FROM events WHERE source_ip = ? ORDER BY created_at DESC LIMIT ?",
            (ip, limit),
        )

    def get_all_events(self, limit: int = 50) -> list[dict]:
        return self.db.fetch_all(
            "SELECT * FROM events ORDER BY created_at DESC LIMIT ?", (limit,)
        )

    def get_stats(self) -> dict:
        total = self.db.fetch_one("SELECT COUNT(*) as count FROM events")
        open_count = self.db.fetch_one("SELECT COUNT(*) as count FROM events WHERE status = 'open'")
        by_severity = self.db.fetch_all(
            "SELECT severity, COUNT(*) as count FROM events GROUP BY severity"
        )
        return {
            "total": total["count"] if total else 0,
            "open": open_count["count"] if open_count else 0,
            "by_severity": {r["severity"]: r["count"] for r in by_severity},
        }
