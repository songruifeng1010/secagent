import uuid
from datetime import datetime, timezone
from typing import Optional, Any
from dataclasses import dataclass, field, asdict


@dataclass
class SecurityEvent:
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    severity: str = "低危"
    status: str = "open"
    source_ip: str = ""
    alert_type: str = ""
    mitre_tactic_id: str = ""
    mitre_technique_id: str = ""
    description: str = ""
    resolution: str = ""
    resolved_by: str = ""
    raw_data: dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def is_high_risk(self) -> bool:
        return self.severity in ("高危", "紧急")


@dataclass
class Alert:
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    description: str = ""
    source_ip: str = "0.0.0.0"
    severity: str = "低危"
    alert_type: str = "未知"
    raw_data: dict = field(default_factory=dict)
    is_false_positive: bool = False
    filter_reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IoCEntry:
    ioc_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ioc_type: str = ""  # ip / domain / hash / url
    ioc_value: str = ""
    threat_type: str = ""
    confidence: float = 0.0
    source: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

