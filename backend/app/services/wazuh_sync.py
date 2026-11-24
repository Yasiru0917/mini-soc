"""Import Wazuh alerts into Mini SOC.

Each Wazuh alert becomes a Mini SOC alert with source="wazuh" and
raw_reference="wazuh:<indexer document id>", so it always points back to the
original record in Wazuh. Re-running the sync never creates duplicates.

Severity mapping (Wazuh rule levels run 0-15):
    12-15 critical | 10-11 high | 7-9 medium | 4-6 low | 0-3 info
"""

import ipaddress
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import utcnow
from app.integrations.wazuh.client import WazuhClient
from app.models import Alert
from app.models.enums import AlertSource, Severity
from app.services import settings_store

CURSOR_KEY = "wazuh_last_alert_timestamp"

# Tests replace this factory to inject a fake Wazuh server.
client_factory: Callable[[Settings], WazuhClient] = WazuhClient


def level_to_severity(level: int) -> Severity:
    if level >= 12:
        return Severity.CRITICAL
    if level >= 10:
        return Severity.HIGH
    if level >= 7:
        return Severity.MEDIUM
    if level >= 4:
        return Severity.LOW
    return Severity.INFO


def _ip_or_none(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value))) if value else None
    except ValueError:
        return None


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # Wazuh format: 2026-11-24T10:00:00.123+0000
        ts = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        try:
            ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return ts.astimezone(UTC)


def to_alert(hit: dict) -> Alert:
    src = hit.get("_source", {})
    rule, agent, data = src.get("rule", {}), src.get("agent", {}), src.get("data", {})
    level = int(rule.get("level", 0))
    mitre = ", ".join(rule.get("mitre", {}).get("id", [])) or "none listed"
    description = (
        f"Wazuh rule {rule.get('id')} (level {level}): {rule.get('description', '')}\n"
        f"Agent: {agent.get('name', '?')} (id {agent.get('id', '?')}, {agent.get('ip', 'no ip')})\n"
        f"Groups: {', '.join(rule.get('groups', [])) or '-'}\nMITRE ATT&CK: {mitre}\n"
        f"Location: {src.get('location', '-')}\n\nFull log:\n{str(src.get('full_log', ''))[:1500]}"
    )
    return Alert(
        title=f"Wazuh: {rule.get('description', 'alert')}"[:200],
        description=description[:5000],
        severity=level_to_severity(level),
        source=AlertSource.WAZUH,
        is_simulated=False,
        detection_rule_id=f"WZ-{rule.get('id', '?')}"[:32],
        src_ip=_ip_or_none(data.get("srcip")),
        dst_ip=_ip_or_none(agent.get("ip")),
        raw_reference=f"wazuh:{hit.get('_id')}"[:255],
        detected_at=_parse_ts(src.get("timestamp")) or utcnow(),
    )


def sync_alerts(db: Session, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    cursor_text = settings_store.get_value(db, CURSOR_KEY)
    since = _parse_ts(cursor_text) if cursor_text else utcnow() - timedelta(hours=24)

    with client_factory(settings) as client:
        hits = client.search_alerts(since, settings.wazuh_min_rule_level)

    created = duplicates = 0
    newest = since
    for hit in hits:
        ref = f"wazuh:{hit.get('_id')}"
        alert = to_alert(hit)
        newest = max(newest, alert.detected_at)
        if db.scalar(select(Alert.id).where(Alert.raw_reference == ref)):
            duplicates += 1
            continue
        db.add(alert)
        created += 1
    db.commit()
    settings_store.set_value(db, CURSOR_KEY, newest.isoformat())
    return {"fetched": len(hits), "created": created, "duplicates": duplicates, "since": since.isoformat(),
            "cursor": newest.isoformat(), "min_rule_level": settings.wazuh_min_rule_level}
