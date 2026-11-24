"""Alert request/response shapes."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import AlertSource, AlertStatus, Severity
from app.schemas.common import OptionalIP


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: str | None
    severity: Severity
    status: AlertStatus
    source: AlertSource
    is_simulated: bool
    detection_rule_id: str | None
    raw_reference: str | None
    src_ip: str | None
    dst_ip: str | None
    incident_id: int | None
    detected_at: datetime
    created_at: datetime
    updated_at: datetime


class AlertCreate(BaseModel):
    """Manual alert raised by an analyst. The server forces source='manual':
    a user can never create an alert that claims to come from a detector."""

    title: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    severity: Severity
    src_ip: OptionalIP = None
    dst_ip: OptionalIP = None


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    severity: Severity | None = None
