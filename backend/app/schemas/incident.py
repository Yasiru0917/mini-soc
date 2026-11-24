"""Incident, note and evidence shapes."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import IncidentStatus, Severity
from app.schemas.alert import AlertOut


class IncidentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    severity: Severity
    status: IncidentStatus
    is_simulated: bool
    assignee_id: int | None
    assignee: str | None = None
    alert_count: int = 0
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


class NoteOut(BaseModel):
    id: int
    author: str | None
    body: str
    created_at: datetime


class EvidenceOut(BaseModel):
    id: int
    description: str | None
    original_name: str | None
    content_type: str | None
    size_bytes: int | None
    sha256: str | None
    uploaded_by: str | None
    created_at: datetime
    has_file: bool


class IncidentDetail(IncidentSummary):
    description: str | None
    resolution: str | None
    recommendations: str | None
    created_by: str | None
    alerts: list[AlertOut]
    notes: list[NoteOut]
    evidence: list[EvidenceOut]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    severity: Severity | None = None  # default: worst severity of the linked alerts
    alert_ids: list[int] = Field(default_factory=list, max_length=500)
    assignee_id: int | None = None


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    severity: Severity | None = None
    status: IncidentStatus | None = None
    assignee_id: int | None = None  # send null explicitly to unassign
    resolution: str | None = Field(default=None, max_length=10_000)
    recommendations: str | None = Field(default=None, max_length=10_000)


class AlertLink(BaseModel):
    alert_ids: list[int] = Field(min_length=1, max_length=500)


class NoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=10_000)


class AssignableUser(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
