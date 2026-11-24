"""Analyse an uploaded file: parse -> store events -> run rules -> raise alerts."""

import json

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import utcnow
from app.detection import parsers
from app.detection.events import OTHER, Detection
from app.detection.rules import run_log_rules
from app.integrations.tshark import analyzer
from app.models import Alert, LogUpload, ParsedEvent, User
from app.models.enums import AlertSource
from app.services.uploads import StoredFile

TEXT_TYPES = ("auth", "access", "jsonl")


class AnalysisError(Exception):
    pass


def _alert_from_detection(upload: LogUpload, d: Detection, source: AlertSource) -> Alert:
    lines = ""
    if d.line_numbers:
        lines = f":lines:{d.line_numbers[0]}-{d.line_numbers[-1]}"
    window = ""
    if d.first_seen and d.last_seen:
        window = f"\nActivity window (UTC): {d.first_seen:%Y-%m-%d %H:%M:%S} to {d.last_seen:%Y-%m-%d %H:%M:%S}."
    samples = "\n\nSample lines:\n" + "\n".join(d.samples) if d.samples else ""
    return Alert(
        title=d.title[:200],
        description=(f"{d.details}{window}\nMITRE ATT&CK: {d.mitre}\n"
                     f"Source file: {upload.original_name} (upload #{upload.id}, SHA-256 {upload.sha256[:16]}…)"
                     f"{samples}")[:5000],
        severity=d.severity,
        source=source,
        is_simulated=False,
        detection_rule_id=d.rule_id,
        src_ip=d.src_ip,
        dst_ip=d.dst_ip,
        raw_reference=f"upload:{upload.id}{lines}"[:255],
        # When the activity happened (from the log), not when we analysed it.
        detected_at=d.last_seen or utcnow(),
    )


def analyse(db: Session, stored: StoredFile, requested_type: str, user: User) -> LogUpload:
    log_type = "pcap" if stored.kind == "pcap" else requested_type
    if stored.kind == "pcap" and requested_type not in ("auto", "pcap"):
        raise AnalysisError("This is a packet capture; choose 'Packet capture' or 'Auto-detect'.")
    if stored.kind != "pcap" and requested_type == "pcap":
        raise AnalysisError("This is a text file, not a packet capture.")

    upload = LogUpload(original_name=stored.original_name, stored_name=stored.stored_name, sha256=stored.sha256,
                       size_bytes=stored.size, log_type=log_type, status="processed", uploaded_by_id=user.id)
    db.add(upload)
    db.flush()

    if log_type == "pcap":
        _analyse_pcap(db, upload, stored)
    else:
        _analyse_text(db, upload, stored, log_type)
    db.commit()
    return upload


def _analyse_text(db: Session, upload: LogUpload, stored: StoredFile, log_type: str) -> None:
    lines = stored.path.read_text(encoding="utf-8").splitlines()
    upload.lines_total = len(lines)
    if log_type == "auto":
        detected = parsers.detect_format(lines)
        if detected is None:
            raise AnalysisError("Could not recognise the log format. Supported: Linux auth.log, "
                                "Apache/Nginx access log, JSON lines. Choose the type manually if unsure.")
        upload.log_type = log_type = detected

    events, skipped = parsers.parse_lines(log_type, lines)
    upload.events_parsed, upload.lines_skipped = len(events), skipped

    # Store recognised security-relevant events for browsing (bulk insert = fast).
    db.add_all([
        ParsedEvent(upload_id=upload.id, line_no=e.line_no, timestamp=e.timestamp, event_type=e.event_type,
                    src_ip=e.src_ip, user=e.user,
                    detail=(f"{e.method} {e.path} -> {e.status}" if e.path else e.message)[:600])
        for e in events if e.event_type != OTHER
    ])

    detections = run_log_rules(events)
    for d in detections:
        db.add(_alert_from_detection(upload, d, AlertSource.LOG_RULE))
    upload.alerts_raised = len(detections)
    upload.summary_json = json.dumps({
        "rule_hits": [{"rule_id": d.rule_id, "title": d.title, "count": d.count} for d in detections],
    })


def _analyse_pcap(db: Session, upload: LogUpload, stored: StoredFile) -> None:
    settings = get_settings()
    try:
        cmd = analyzer.build_command(settings.tshark_path, stored.path)
        summary, detections = analyzer.summarise(analyzer.run_tshark(cmd, settings.tshark_timeout_seconds))
    except analyzer.TsharkError as exc:
        raise AnalysisError(str(exc)) from None
    upload.events_parsed = summary["packets"]
    for d in detections:
        db.add(_alert_from_detection(upload, d, AlertSource.PCAP))
    upload.alerts_raised = len(detections)
    summary["rule_hits"] = [{"rule_id": d.rule_id, "title": d.title, "count": d.count} for d in detections]
    upload.summary_json = json.dumps(summary)
