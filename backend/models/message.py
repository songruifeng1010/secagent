import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
from dataclasses import dataclass, field, asdict


class MessageType(Enum):
    TASK_ASSIGN = "task_assign"
    TASK_RESULT = "task_result"
    QUERY = "query"
    QUERY_RESULT = "query_result"
    ALERT = "alert"
    REQUEST_APPROVAL = "request_approval"
    APPROVAL_RESULT = "approval_result"
    STATUS_UPDATE = "status_update"
    ERROR = "error"
    CHAT = "chat"


@dataclass
class AgentMessage:
    msg_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    sender: str = ""
    receiver: str = ""
    msg_type: MessageType = MessageType.CHAT
    payload: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    priority: int = 0
    requires_response: bool = False

    def to_dict(self) -> dict:
        base = asdict(self)
        base["msg_type"] = self.msg_type.value
        return base

    @classmethod
    def from_dict(cls, data: dict) -> "AgentMessage":
        data["msg_type"] = MessageType(data.get("msg_type", "chat"))
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Task:
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent_id: str = ""
    task_type: str = ""
    params: dict = field(default_factory=dict)
    status: str = "pending"
    result: Optional[dict] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

