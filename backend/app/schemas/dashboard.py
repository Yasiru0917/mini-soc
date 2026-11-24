"""Dashboard summary response."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import AlertSource, AlertStatus, IncidentStatus, Severity


class AlertCounts(BaseModel):
    total: int
    by_severity: dict[Severity, int]
    simulated: int  # how many of `total` are demo records


class IncidentCounts(BaseModel):
    total: int
    open: int
    by_status: dict[IncidentStatus, int]


class RecentAlert(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    severity: Severity
    status: AlertStatus
    source: AlertSource
    is_simulated: bool
    src_ip: str | None
    dst_ip: str | None
    detected_at: datetime


class NetworkCounts(BaseModel):
    devices: int
    devices_up_24h: int
    open_ports: int
    scans_completed: int
    last_scan_at: datetime | None


class DashboardSummary(BaseModel):
    alerts: AlertCounts
    alerts_by_source: dict[str, int]
    incidents: IncidentCounts
    network: NetworkCounts
    recent_alerts: list[RecentAlert]
    includes_simulated: bool
    generated_at: datetime
