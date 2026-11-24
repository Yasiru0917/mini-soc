"""Report downloads (PDF / CSV) and report history."""

import hashlib

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require_role
from app.api.v1.incidents import _detail, _get_incident
from app.db.session import get_db, utcnow
from app.models import Alert, GeneratedReport, User
from app.models.enums import AlertSource, AlertStatus, Role, Severity
from app.reports.csv_export import ALERT_HEADER, alert_rows, to_csv
from app.reports.pdf import build_incident_pdf
from app.services import audit

router = APIRouter(prefix="/reports", tags=["reports"])


def _deliver(db: Session, request: Request, user: User, kind: str, filename: str, content: bytes,
             media_type: str, incident_id: int | None = None) -> Response:
    digest = hashlib.sha256(content).hexdigest()
    db.add(GeneratedReport(kind=kind, incident_id=incident_id, filename=filename, sha256=digest,
                           size_bytes=len(content), generated_by_id=user.id))
    db.commit()
    audit.record(db, action="report.generate", outcome="success", user=user, target=filename,
                 detail=f"sha256={digest}", client_ip=client_ip(request))
    return Response(content, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Report-SHA256": digest,  # lets the recipient verify the file
    })


@router.get("/incidents/{incident_id}.pdf")
def incident_pdf(incident_id: int, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_role(Role.VIEWER))):
    detail = _detail(db, _get_incident(db, incident_id))
    pdf = build_incident_pdf(detail, user.username)
    return _deliver(db, request, user, "incident_pdf", f"incident-{incident_id}-{utcnow():%Y%m%d}.pdf", pdf,
                    "application/pdf", incident_id)


@router.get("/incidents/{incident_id}.csv")
def incident_csv(incident_id: int, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_role(Role.VIEWER))):
    inc = _detail(db, _get_incident(db, incident_id))
    rows = [["incident", inc.id, inc.title, inc.severity, inc.status, inc.created_at, inc.closed_at,
             inc.assignee, inc.is_simulated, inc.resolution, inc.recommendations]]
    rows += [["alert", a.id, a.title, a.severity, a.status, a.detected_at, None, a.source, a.is_simulated,
              f"{a.src_ip or ''} -> {a.dst_ip or ''}", a.detection_rule_id] for a in inc.alerts]
    rows += [["note", n.id, n.body, None, None, n.created_at, None, n.author, None, None, None] for n in inc.notes]
    rows += [["evidence", e.id, e.original_name or e.description, None, None, e.created_at, None, e.uploaded_by,
              None, e.sha256, e.description] for e in inc.evidence]
    header = ["record", "id", "title/body", "severity", "status", "time_utc", "closed_utc", "who/source",
              "simulated", "detail", "extra"]
    return _deliver(db, request, user, "incident_csv", f"incident-{incident_id}-{utcnow():%Y%m%d}.csv",
                    to_csv(header, rows), "text/csv; charset=utf-8", incident_id)


@router.get("/alerts.csv")
def alerts_csv(request: Request, severity: Severity | None = None,
               status_: AlertStatus | None = Query(None, alias="status"),
               source: AlertSource | None = None, include_simulated: bool = True,
               db: Session = Depends(get_db), user: User = Depends(require_role(Role.VIEWER))):
    filters = []
    if severity:
        filters.append(Alert.severity == severity)
    if status_:
        filters.append(Alert.status == status_)
    if source:
        filters.append(Alert.source == source)
    if not include_simulated:
        filters.append(Alert.is_simulated.is_(False))
    alerts = db.scalars(select(Alert).where(*filters).order_by(Alert.detected_at.desc()).limit(50_000)).all()
    return _deliver(db, request, user, "alerts_csv", f"alerts-{utcnow():%Y%m%d-%H%M}.csv",
                    to_csv(ALERT_HEADER, alert_rows(alerts)), "text/csv; charset=utf-8")


@router.get("")
def report_history(limit: int = Query(30, ge=1, le=200), db: Session = Depends(get_db),
                   _user: User = Depends(require_role(Role.VIEWER))) -> list[dict]:
    rows = db.scalars(select(GeneratedReport).order_by(GeneratedReport.generated_at.desc()).limit(limit)).all()
    names = dict(db.execute(select(User.id, User.username)).all())
    return [{"id": r.id, "kind": r.kind, "incident_id": r.incident_id, "filename": r.filename, "sha256": r.sha256,
             "size_bytes": r.size_bytes, "generated_by": names.get(r.generated_by_id),
             "generated_at": r.generated_at.isoformat()} for r in rows]
