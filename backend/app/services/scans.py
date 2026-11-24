"""Scan lifecycle: validate -> queue -> run Nmap in the background -> store results.

The HTTP request returns immediately (202 Accepted) with a scan ID; the
browser then polls GET /scans/{id} until the status is completed/failed.
"""

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import SessionLocal, utcnow
from app.integrations.nmap import runner
from app.integrations.nmap.findings import Finding, new_device_finding, risky_port_findings
from app.models import Alert, Device, DevicePort, Scan
from app.models.enums import AlertSource, AlertStatus

logger = logging.getLogger("mini_soc.scans")

ACTIVE_STATES = ("queued", "running")
OPEN_ALERT_STATES = (AlertStatus.NEW, AlertStatus.INVESTIGATING)


def has_active_scan(db: Session) -> bool:
    return db.scalar(select(Scan.id).where(Scan.status.in_(ACTIVE_STATES)).limit(1)) is not None


def fail_interrupted_scans(db: Session) -> None:
    """At startup: scans left 'running' by a crash/restart can never finish."""
    for scan in db.scalars(select(Scan).where(Scan.status.in_(ACTIVE_STATES))):
        scan.status, scan.error, scan.finished_at = "failed", "Interrupted by server restart", utcnow()
    db.commit()


def execute_scan(scan_id: int) -> None:
    """Background task. Uses its own DB session (the request's session is closed by now)."""
    settings = get_settings()
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status, scan.started_at = "running", utcnow()
        db.commit()
        try:
            command = runner.build_command(settings.nmap_path, scan.profile, scan.target)
            scan.command = " ".join(command)
            db.commit()
            hosts = runner.parse_xml(runner.run_nmap(command, settings.scan_timeout_seconds))
            store_results(db, scan, hosts)
            scan.status = "completed"
        except runner.NmapError as exc:
            scan.status, scan.error = "failed", str(exc)
        except Exception:  # never leave a scan stuck in "running"
            logger.exception("Scan %s crashed", scan_id)
            scan.status, scan.error = "failed", "Internal error while processing scan results (see server log)"
        scan.finished_at = utcnow()
        db.commit()


def store_results(db: Session, scan: Scan, hosts: list[runner.HostResult]) -> None:
    now = utcnow()
    had_baseline = db.scalar(select(Device.id).limit(1)) is not None
    findings: list[Finding] = []
    hosts_up = open_ports = 0

    for host in hosts:
        if host.state != "up":
            continue
        hosts_up += 1
        device = db.scalar(select(Device).where(Device.ip == host.ip))
        if device is None:
            device = Device(ip=host.ip, first_seen=now)
            db.add(device)
            if had_baseline:
                findings.append(new_device_finding(host.ip, host.hostname))
        device.hostname = host.hostname or device.hostname
        device.mac = host.mac or device.mac
        device.vendor = host.vendor or device.vendor
        device.state, device.last_seen, device.last_scan_id = "up", now, scan.id
        db.flush()

        host_open = []
        for p in host.ports:
            row = db.scalar(select(DevicePort).where(
                DevicePort.device_id == device.id, DevicePort.port == p.port, DevicePort.protocol == p.protocol))
            if row is None:
                row = DevicePort(device_id=device.id, port=p.port, protocol=p.protocol, first_seen=now)
                db.add(row)
            row.state, row.last_seen, row.last_scan_id = p.state, now, scan.id
            row.service = p.service or row.service
            row.product, row.version = p.product or row.product, p.version or row.version
            if p.state == "open":
                open_ports += 1
                host_open.append((p.port, p.protocol, p.service))
        findings.extend(risky_port_findings(host.ip, host_open))

    scan.hosts_up, scan.open_ports = hosts_up, open_ports
    scan.alerts_raised = raise_alerts(db, scan, findings)


def raise_alerts(db: Session, scan: Scan, findings: list[Finding]) -> int:
    """Create alerts, skipping ones that duplicate an alert that is still open."""
    created = 0
    for f in findings:
        duplicate = db.scalar(select(Alert.id).where(
            Alert.source == AlertSource.NMAP, Alert.detection_rule_id == f.rule_id,
            Alert.title == f.title, Alert.status.in_(OPEN_ALERT_STATES)).limit(1))
        if duplicate:
            continue
        db.add(Alert(
            title=f.title, description=f.description, severity=f.severity, source=AlertSource.NMAP,
            is_simulated=False, detection_rule_id=f.rule_id, dst_ip=f.host_ip,
            raw_reference=f"scan:{scan.id}", detected_at=utcnow(),
        ))
        created += 1
    return created
