"""Import every model here so `Base.metadata` knows about all tables."""

from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.incident import Evidence, Incident, IncidentNote
from app.models.network import AppSetting, Device, DevicePort, Scan
from app.models.user import User

__all__ = [
    "Alert", "AppSetting", "AuditLog", "Device", "DevicePort", "Evidence", "Incident",
    "IncidentNote", "Scan", "User",
]
