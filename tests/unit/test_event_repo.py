"""
测试 EventRepository — 事件仓库
"""
import os
import tempfile
import pytest
from backend.storage.database import Database, Repository
from backend.storage.repositories.event_repo import EventRepository


@pytest.fixture
def db():
    """创建临时 SQLite 数据库供测试使用"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    database = Database(db_path)
    from backend.storage.models import SCHEMA_SQL
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()
    yield database
    database.close()
    os.unlink(db_path)


@pytest.fixture
def repo(db):
    return EventRepository(db)


class TestCreateEvent:
    def test_create_event_returns_id(self, repo):
        eid = repo.create_event(title="测试事件", severity="高危")
        assert eid is not None
        assert len(eid) == 12

    def test_create_event_with_all_fields(self, repo):
        eid = repo.create_event(
            title="SQL注入", severity="紧急",
            source_ip="1.2.3.4", alert_type="sql_injection",
            mitre_tactic_id="TA0001", mitre_technique_id="T1190",
            description="检测到注入",
        )
        events = repo.get_all_events()
        assert len(events) == 1
        assert events[0]["title"] == "SQL注入"
        assert events[0]["severity"] == "紧急"
        assert events[0]["source_ip"] == "1.2.3.4"
        assert events[0]["mitre_tactic_id"] == "TA0001"

    def test_create_multiple_events(self, repo):
        repo.create_event(title="事件A")
        repo.create_event(title="事件B")
        repo.create_event(title="事件C")
        assert len(repo.get_all_events()) == 3


class TestResolveEvent:
    def test_resolve_event(self, repo):
        eid = repo.create_event(title="待处理")
        repo.resolve_event(eid, resolution="已修复", resolved_by="admin")
        open_events = repo.get_open_events()
        assert all(e["id"] != eid for e in open_events)

    def test_resolve_twice(self, repo):
        eid = repo.create_event(title="重复解决")
        repo.resolve_event(eid, "已修复")
        repo.resolve_event(eid, "再次修复")


class TestGetOpenEvents:
    def test_open_events_empty(self, repo):
        assert repo.get_open_events() == []

    def test_open_events_after_create(self, repo):
        repo.create_event(title="新事件")
        events = repo.get_open_events()
        assert len(events) == 1
        assert events[0]["status"] == "open"

    def test_open_events_filter_by_severity(self, repo):
        repo.create_event(title="低危事件", severity="低危")
        repo.create_event(title="高危事件", severity="高危")
        repo.create_event(title="中危事件", severity="中危")
        high = repo.get_open_events(severity="高危")
        assert len(high) == 1
        assert high[0]["title"] == "高危事件"

    def test_open_events_after_resolve(self, repo):
        eid = repo.create_event(title="已解决")
        repo.resolve_event(eid, "done")
        assert repo.get_open_events() == []


class TestGetEventsByIp:
    def test_no_events_for_ip(self, repo):
        assert repo.get_events_by_ip("10.0.0.1") == []

    def test_events_by_ip(self, repo):
        repo.create_event(title="事件A", source_ip="10.0.0.1")
        repo.create_event(title="事件B", source_ip="10.0.0.2")
        repo.create_event(title="事件C", source_ip="10.0.0.1")
        events = repo.get_events_by_ip("10.0.0.1")
        assert len(events) == 2
        assert all(e["source_ip"] == "10.0.0.1" for e in events)

    def test_events_by_ip_limit(self, repo):
        for i in range(5):
            repo.create_event(title=f"事件{i}", source_ip="10.0.0.1")
        events = repo.get_events_by_ip("10.0.0.1", limit=3)
        assert len(events) == 3


class TestGetAllEvents:
    def test_all_events_empty(self, repo):
        assert repo.get_all_events() == []

    def test_all_events_order(self, repo):
        repo.create_event(title="事件A")
        repo.create_event(title="事件B")
        repo.create_event(title="事件C")
        events = repo.get_all_events()
        assert len(events) == 3

    def test_all_events_limit(self, repo):
        for i in range(10):
            repo.create_event(title=f"事件{i}")
        events = repo.get_all_events(limit=3)
        assert len(events) == 3


class TestGetStats:
    def test_stats_empty(self, repo):
        stats = repo.get_stats()
        assert stats["total"] == 0
        assert stats["open"] == 0
        assert stats["by_severity"] == {}

    def test_stats_with_events(self, repo):
        repo.create_event(title="高危A", severity="高危")
        repo.create_event(title="高危B", severity="高危")
        repo.create_event(title="低危A", severity="低危")
        stats = repo.get_stats()
        assert stats["total"] == 3
        assert stats["open"] == 3
        assert stats["by_severity"]["高危"] == 2
        assert stats["by_severity"]["低危"] == 1

    def test_stats_after_resolve(self, repo):
        eid = repo.create_event(title="已解决")
        repo.create_event(title="未解决")
        repo.resolve_event(eid, "done")
        stats = repo.get_stats()
        assert stats["total"] == 2
        assert stats["open"] == 1


class TestInitError:
    def test_init_with_repository_raises(self):
        """EventRepository 不接收 Repository 实例"""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            database = Database(db_path)
            repo_instance = Repository(database)
            with pytest.raises(TypeError, match="EventRepository 需要 Database"):
                EventRepository(db=repo_instance)
        finally:
            os.unlink(db_path)
