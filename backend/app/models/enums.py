"""Fixed value lists shared by models, schemas and the API.

StrEnum values are plain strings in JSON and in the database, but Python
and Pydantic reject anything not in the list. That is input validation for free.
"""

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Higher number = more privileges. Used by require_role(): "analyst or above".
ROLE_LEVEL = {Role.VIEWER: 1, Role.ANALYST: 2, Role.ADMIN: 3}


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class IncidentStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


# Statuses that still need analyst work.
OPEN_INCIDENT_STATUSES = (IncidentStatus.NEW, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED)


class AlertSource(StrEnum):
    """Which mechanism produced an alert (data provenance - see docs/SECURITY.md)."""

    NMAP = "nmap"
    LOG_RULE = "log_rule"
    PCAP = "pcap"
    WAZUH = "wazuh"
    THREAT_INTEL = "threat_intel"
    MANUAL = "manual"
    DEMO = "demo"
