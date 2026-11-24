"""The normalised event and detection shapes shared by parsers and rules."""

from dataclasses import dataclass, field
from datetime import datetime

from app.models.enums import Severity

# Event types produced by parsers
AUTH_FAILURE = "auth_failure"
AUTH_SUCCESS = "auth_success"
INVALID_USER = "invalid_user"
HTTP_REQUEST = "http_request"
OTHER = "other"


@dataclass
class LogEvent:
    line_no: int
    event_type: str
    timestamp: datetime | None = None
    src_ip: str | None = None
    user: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    message: str = ""
    raw: str = ""


@dataclass
class Detection:
    rule_id: str
    title: str
    severity: Severity
    mitre: str
    src_ip: str | None
    dst_ip: str | None = None
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    line_numbers: list[int] = field(default_factory=list)
    samples: list[str] = field(default_factory=list)
    details: str = ""
