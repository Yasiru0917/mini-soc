"""Create or remove clearly-labelled DEMO data.

Demo data lets you explore the UI before real detection sources exist.
Every record created here is marked in three ways, so it can never be
mistaken for a real detection:
  * source = "demo" and is_simulated = True  (shown as a purple DEMO badge)
  * titles start with "[DEMO]"
  * IP addresses come from RFC 5737 "documentation" ranges
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are reserved
    for examples and never used by real hosts.

Usage (backend folder, venv active):
    python -m scripts.seed_demo_data            # add demo data
    python -m scripts.seed_demo_data --remove   # delete ALL demo data
"""

import argparse
from datetime import timedelta

from sqlalchemy import delete, select

from app.db.migrate import upgrade_database
from app.db.session import SessionLocal, utcnow
from app.models import Alert, Incident
from app.models.enums import AlertSource, AlertStatus, IncidentStatus, Severity

DEMO_ALERTS = [
    ("SSH brute force against lab server", Severity.HIGH, "203.0.113.45", "198.51.100.10", "R-001", 5),
    ("Successful SSH login after repeated failures", Severity.CRITICAL, "203.0.113.45", "198.51.100.10", "R-002", 4),
    ("Path traversal attempt on web server", Severity.HIGH, "192.0.2.77", "198.51.100.20", "R-003", 30),
    ("SQL injection pattern in query string", Severity.HIGH, "192.0.2.77", "198.51.100.20", "R-004", 28),
    ("Web directory enumeration (many 404s)", Severity.MEDIUM, "192.0.2.80", "198.51.100.20", "R-005", 60),
    ("Telnet service exposed", Severity.MEDIUM, None, "198.51.100.30", "NMAP-RISKY-PORT", 90),
    ("New device discovered on lab network", Severity.LOW, None, "198.51.100.31", "NMAP-NEW-DEVICE", 120),
    ("Outbound DNS query to newly registered domain", Severity.INFO, "198.51.100.10", "192.0.2.53", None, 200),
]


def seed() -> None:
    now = utcnow()
    with SessionLocal() as db:
        alerts = []
        for title, sev, src, dst, rule, minutes_ago in DEMO_ALERTS:
            alert = Alert(
                title=f"[DEMO] {title}", severity=sev, source=AlertSource.DEMO, is_simulated=True,
                detection_rule_id=rule, src_ip=src, dst_ip=dst, raw_reference="demo:seed_demo_data.py",
                description="Simulated record created by scripts/seed_demo_data.py. Not a real detection.",
                detected_at=now - timedelta(minutes=minutes_ago),
            )
            db.add(alert)
            alerts.append(alert)
        db.flush()

        incident = Incident(
            title="[DEMO] Compromised SSH account on lab server", severity=Severity.CRITICAL,
            status=IncidentStatus.INVESTIGATING, is_simulated=True,
            description="Simulated incident built from demo alerts, for UI demonstration only.",
        )
        db.add(incident)
        db.flush()
        for alert in alerts[:2]:
            alert.incident_id = incident.id
            alert.status = AlertStatus.INVESTIGATING
        db.commit()
        print(f"Created {len(alerts)} demo alerts and 1 demo incident (all marked DEMO).")


def remove() -> None:
    with SessionLocal() as db:
        n_alerts = db.execute(delete(Alert).where(Alert.is_simulated.is_(True))).rowcount
        ids = db.scalars(select(Incident.id).where(Incident.is_simulated.is_(True))).all()
        db.execute(delete(Incident).where(Incident.id.in_(ids)))
        db.commit()
        print(f"Removed {n_alerts} demo alerts and {len(ids)} demo incidents.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--remove", action="store_true", help="delete all demo data")
    args = parser.parse_args()
    upgrade_database()
    remove() if args.remove else seed()
