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


# Used to sort severities and pick the "worst" one (higher = worse).
SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


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

# --- Investigation workflow ---------------------------------------------------
# Which status changes are allowed. A workflow stops mistakes such as closing
# an alert that nobody looked at, and makes the process auditable.
ALERT_TRANSITIONS: dict[AlertStatus, set[AlertStatus]] = {
    AlertStatus.NEW: {AlertStatus.INVESTIGATING, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE},
    AlertStatus.INVESTIGATING: {AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE, AlertStatus.NEW},
    AlertStatus.RESOLVED: {AlertStatus.CLOSED, AlertStatus.INVESTIGATING},
    AlertStatus.FALSE_POSITIVE: {AlertStatus.CLOSED, AlertStatus.INVESTIGATING},
    AlertStatus.CLOSED: {AlertStatus.INVESTIGATING},  # re-open
}

INCIDENT_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.NEW: {IncidentStatus.INVESTIGATING, IncidentStatus.FALSE_POSITIVE},
    IncidentStatus.INVESTIGATING: {IncidentStatus.CONTAINED, IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE},
    IncidentStatus.CONTAINED: {IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING},
    IncidentStatus.RESOLVED: {IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING},
    IncidentStatus.FALSE_POSITIVE: {IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING},
    IncidentStatus.CLOSED: {IncidentStatus.INVESTIGATING},  # re-open
}

# Moving an incident into these states requires a written resolution/justification.
INCIDENT_NEEDS_RESOLUTION = {IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE, IncidentStatus.CLOSED}


class AlertSource(StrEnum):
    """Which mechanism produced an alert (data provenance - see docs/SECURITY.md)."""

    NMAP = "nmap"
    LOG_RULE = "log_rule"
    PCAP = "pcap"
    WAZUH = "wazuh"
    THREAT_INTEL = "threat_intel"
    MANUAL = "manual"
    DEMO = "demo"
