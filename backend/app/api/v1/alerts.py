"""Security alerts: list, view, create (manual), triage."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require_role
from app.db.session import get_db
from app.models import Alert, User
from app.models.enums import ALERT_TRANSITIONS, AlertSource, AlertStatus, Role, Severity
from app.schemas.alert import AlertCreate, AlertOut, AlertUpdate
from app.schemas.common import Page
from app.services import audit

router = APIRouter(prefix="/alerts", tags=["alerts"])


def get_alert_or_404(db: Session, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.get("", response_model=Page[AlertOut])
def list_alerts(
    severity: Severity | None = None,
    status_: AlertStatus | None = Query(None, alias="status"),
    source: AlertSource | None = None,
    q: str | None = Query(None, max_length=100, description="Search title, IPs or rule ID"),
    include_simulated: bool = True,
    unlinked: bool = Query(False, description="Only alerts not attached to an incident"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(Role.VIEWER)),
):
    filters = []
    if severity:
        filters.append(Alert.severity == severity)
    if status_:
        filters.append(Alert.status == status_)
    if source:
        filters.append(Alert.source == source)
    if not include_simulated:
        filters.append(Alert.is_simulated.is_(False))
    if unlinked:
        filters.append(Alert.incident_id.is_(None))
    if q:
        # Parameterised LIKE: the search text is data, never SQL. Escape wildcards too.
        term = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        filters.append(or_(
            Alert.title.ilike(term, escape="\\"),
            Alert.src_ip.ilike(term, escape="\\"),
            Alert.dst_ip.ilike(term, escape="\\"),
            Alert.detection_rule_id.ilike(term, escape="\\"),
        ))

    total = db.scalar(select(func.count()).select_from(Alert).where(*filters)) or 0
    items = db.scalars(
        select(Alert).where(*filters).order_by(Alert.detected_at.desc(), Alert.id.desc()).limit(limit).offset(offset)
    ).all()
    return Page[AlertOut](items=[AlertOut.model_validate(a) for a in items], total=total)


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db), _user: User = Depends(require_role(Role.VIEWER))):
    return get_alert_or_404(db, alert_id)


@router.post("", response_model=AlertOut, status_code=status.HTTP_201_CREATED)
def create_alert(body: AlertCreate, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_role(Role.ANALYST))):
    alert = Alert(
        title=body.title,
        description=body.description,
        severity=body.severity,
        src_ip=body.src_ip,
        dst_ip=body.dst_ip,
        source=AlertSource.MANUAL,  # forced: analysts can't impersonate a detector
        is_simulated=False,
        raw_reference=f"manual:user:{user.username}",
    )
    db.add(alert)
    db.commit()
    audit.record(db, action="alert.create", outcome="success", user=user,
                 target=f"alert:{alert.id}", client_ip=client_ip(request))
    return alert


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(alert_id: int, body: AlertUpdate, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_role(Role.ANALYST))):
    alert = get_alert_or_404(db, alert_id)
    changes = []

    if body.status and body.status != alert.status:
        if body.status not in ALERT_TRANSITIONS[alert.status]:
            allowed = ", ".join(sorted(ALERT_TRANSITIONS[alert.status]))
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Cannot change status from '{alert.status}' to '{body.status}'. "
                                       f"Allowed: {allowed}")
        changes.append(f"status {alert.status}->{body.status}")
        alert.status = body.status

    if body.severity and body.severity != alert.severity:
        changes.append(f"severity {alert.severity}->{body.severity}")
        alert.severity = body.severity

    if changes:
        db.commit()
        audit.record(db, action="alert.update", outcome="success", user=user, target=f"alert:{alert.id}",
                     detail="; ".join(changes), client_ip=client_ip(request))
    return alert
