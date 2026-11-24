"""Incident management: create from alerts, triage workflow, notes, evidence."""

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require_role
from app.core.config import get_settings
from app.db.session import get_db, utcnow
from app.models import Alert, Evidence, Incident, IncidentNote, User
from app.models.enums import (
    INCIDENT_NEEDS_RESOLUTION,
    INCIDENT_TRANSITIONS,
    SEVERITY_RANK,
    AlertStatus,
    IncidentStatus,
    Role,
    Severity,
)
from app.schemas.alert import AlertOut
from app.schemas.common import Page
from app.schemas.incident import (
    AlertLink,
    AssignableUser,
    EvidenceOut,
    IncidentCreate,
    IncidentDetail,
    IncidentSummary,
    IncidentUpdate,
    NoteCreate,
    NoteOut,
)
from app.services import audit
from app.services.uploads import UploadRejected, save_upload, stored_path

router = APIRouter(prefix="/incidents", tags=["incidents"])
evidence_router = APIRouter(prefix="/evidence", tags=["incidents"])
assign_router = APIRouter(prefix="/users", tags=["users"])

EVIDENCE_SUBDIR = "evidence"
EVIDENCE_KINDS = {"text", "pcap", "png", "jpeg", "pdf"}


# ---------------------------------------------------------------- helpers
def _get_incident(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


def _usernames(db: Session, ids: set[int | None]) -> dict[int, str]:
    ids = {i for i in ids if i is not None}
    if not ids:
        return {}
    return dict(db.execute(select(User.id, User.username).where(User.id.in_(ids))).all())


def _load_alerts(db: Session, alert_ids: list[int]) -> list[Alert]:
    alerts = db.scalars(select(Alert).where(Alert.id.in_(alert_ids))).all()
    missing = set(alert_ids) - {a.id for a in alerts}
    if missing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Alert(s) not found: {sorted(missing)}")
    return list(alerts)


def _attach_alerts(incident: Incident, alerts: list[Alert]) -> None:
    for alert in alerts:
        if alert.incident_id not in (None, incident.id):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Alert {alert.id} already belongs to incident {alert.incident_id}")
        alert.incident_id = incident.id
        if alert.status == AlertStatus.NEW:
            alert.status = AlertStatus.INVESTIGATING
        # Anything built on demo data is itself marked simulated ("taint" rule).
        if alert.is_simulated:
            incident.is_simulated = True


def _check_assignee(db: Session, assignee_id: int | None) -> None:
    if assignee_id is None:
        return
    assignee = db.get(User, assignee_id)
    if assignee is None or not assignee.is_active or assignee.role == Role.VIEWER:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Assignee must be an active analyst or admin")


def _summary(db: Session, incident: Incident, names: dict[int, str], counts: dict[int, int]) -> IncidentSummary:
    data = IncidentSummary.model_validate(incident)
    data.assignee = names.get(incident.assignee_id)
    data.alert_count = counts.get(incident.id, 0)
    return data


def _detail(db: Session, incident: Incident) -> IncidentDetail:
    alerts = db.scalars(select(Alert).where(Alert.incident_id == incident.id).order_by(Alert.detected_at)).all()
    notes = db.scalars(select(IncidentNote).where(IncidentNote.incident_id == incident.id)
                       .order_by(IncidentNote.created_at)).all()
    evidence = db.scalars(select(Evidence).where(Evidence.incident_id == incident.id)
                          .order_by(Evidence.created_at)).all()
    names = _usernames(db, {incident.assignee_id, incident.created_by_id}
                       | {n.author_id for n in notes} | {e.uploaded_by_id for e in evidence})
    base = _summary(db, incident, names, {incident.id: len(alerts)})
    return IncidentDetail(
        **base.model_dump(),
        description=incident.description,
        resolution=incident.resolution,
        recommendations=incident.recommendations,
        created_by=names.get(incident.created_by_id),
        alerts=[AlertOut.model_validate(a) for a in alerts],
        notes=[NoteOut(id=n.id, author=names.get(n.author_id), body=n.body, created_at=n.created_at) for n in notes],
        evidence=[EvidenceOut(
            id=e.id, description=e.description, original_name=e.original_name, content_type=e.content_type,
            size_bytes=e.size_bytes, sha256=e.sha256, uploaded_by=names.get(e.uploaded_by_id),
            created_at=e.created_at, has_file=e.stored_name is not None,
        ) for e in evidence],
    )


# ---------------------------------------------------------------- incidents
@router.get("", response_model=Page[IncidentSummary])
def list_incidents(
    status_: IncidentStatus | None = Query(None, alias="status"),
    severity: Severity | None = None,
    q: str | None = Query(None, max_length=100),
    open_only: bool = False,
    include_simulated: bool = True,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(Role.VIEWER)),
):
    filters = []
    if status_:
        filters.append(Incident.status == status_)
    if severity:
        filters.append(Incident.severity == severity)
    if open_only:
        filters.append(Incident.status.in_([IncidentStatus.NEW, IncidentStatus.INVESTIGATING,
                                            IncidentStatus.CONTAINED]))
    if not include_simulated:
        filters.append(Incident.is_simulated.is_(False))
    if q:
        term = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        filters.append(or_(Incident.title.ilike(term, escape="\\"), Incident.description.ilike(term, escape="\\")))

    total = db.scalar(select(func.count()).select_from(Incident).where(*filters)) or 0
    incidents = db.scalars(select(Incident).where(*filters)
                           .order_by(Incident.updated_at.desc()).limit(limit).offset(offset)).all()
    ids = [i.id for i in incidents]
    counts = dict(db.execute(select(Alert.incident_id, func.count()).where(Alert.incident_id.in_(ids))
                             .group_by(Alert.incident_id)).all()) if ids else {}
    names = _usernames(db, {i.assignee_id for i in incidents})
    return Page[IncidentSummary](items=[_summary(db, i, names, counts) for i in incidents], total=total)


@router.post("", response_model=IncidentDetail, status_code=status.HTTP_201_CREATED)
def create_incident(body: IncidentCreate, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require_role(Role.ANALYST))):
    alerts = _load_alerts(db, body.alert_ids) if body.alert_ids else []
    severity = body.severity or (max((a.severity for a in alerts), key=SEVERITY_RANK.__getitem__)
                                 if alerts else None)
    if severity is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail="severity is required when no alerts are linked")
    _check_assignee(db, body.assignee_id)

    incident = Incident(title=body.title, description=body.description, severity=severity,
                        assignee_id=body.assignee_id, created_by_id=user.id)
    db.add(incident)
    db.flush()  # get incident.id before linking alerts
    _attach_alerts(incident, alerts)
    db.commit()
    audit.record(db, action="incident.create", outcome="success", user=user, target=f"incident:{incident.id}",
                 detail=f"alerts={body.alert_ids}" if body.alert_ids else None, client_ip=client_ip(request))
    return _detail(db, incident)


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, db: Session = Depends(get_db),
                 _user: User = Depends(require_role(Role.VIEWER))):
    return _detail(db, _get_incident(db, incident_id))


@router.patch("/{incident_id}", response_model=IncidentDetail)
def update_incident(incident_id: int, body: IncidentUpdate, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require_role(Role.ANALYST))):
    incident = _get_incident(db, incident_id)
    sent = body.model_fields_set  # which fields the client actually sent
    changes = []

    for field in ("title", "description", "severity", "resolution", "recommendations"):
        if field in sent and getattr(body, field) is not None and getattr(body, field) != getattr(incident, field):
            setattr(incident, field, getattr(body, field))
            changes.append(field)

    if "assignee_id" in sent and body.assignee_id != incident.assignee_id:
        _check_assignee(db, body.assignee_id)
        incident.assignee_id = body.assignee_id
        changes.append(f"assignee->{body.assignee_id}")

    if body.status and body.status != incident.status:
        if body.status not in INCIDENT_TRANSITIONS[incident.status]:
            allowed = ", ".join(sorted(INCIDENT_TRANSITIONS[incident.status]))
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Cannot change status from '{incident.status}' to '{body.status}'. "
                                       f"Allowed: {allowed}")
        if body.status in INCIDENT_NEEDS_RESOLUTION and not (incident.resolution or "").strip():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                                detail="Write a resolution (root cause and actions, or why it is a false "
                                       "positive) before resolving or closing the incident")
        changes.append(f"status {incident.status}->{body.status}")
        incident.status = body.status
        incident.closed_at = utcnow() if body.status == IncidentStatus.CLOSED else None

    if changes:
        db.commit()
        audit.record(db, action="incident.update", outcome="success", user=user, target=f"incident:{incident.id}",
                     detail="; ".join(changes), client_ip=client_ip(request))
    return _detail(db, incident)


@router.post("/{incident_id}/alerts", response_model=IncidentDetail)
def link_alerts(incident_id: int, body: AlertLink, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_role(Role.ANALYST))):
    incident = _get_incident(db, incident_id)
    _attach_alerts(incident, _load_alerts(db, body.alert_ids))
    db.commit()
    audit.record(db, action="incident.link_alerts", outcome="success", user=user,
                 target=f"incident:{incident.id}", detail=f"alerts={body.alert_ids}", client_ip=client_ip(request))
    return _detail(db, incident)


@router.delete("/{incident_id}/alerts/{alert_id}", response_model=IncidentDetail)
def unlink_alert(incident_id: int, alert_id: int, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_role(Role.ANALYST))):
    incident = _get_incident(db, incident_id)
    alert = db.get(Alert, alert_id)
    if alert is None or alert.incident_id != incident.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert is not linked to this incident")
    alert.incident_id = None
    db.flush()
    # Re-evaluate the simulated flag from the alerts that remain.
    incident.is_simulated = bool(db.scalar(select(func.count()).select_from(Alert).where(
        Alert.incident_id == incident.id, Alert.is_simulated.is_(True))))
    db.commit()
    audit.record(db, action="incident.unlink_alert", outcome="success", user=user,
                 target=f"incident:{incident.id}", detail=f"alert={alert_id}", client_ip=client_ip(request))
    return _detail(db, incident)


# ---------------------------------------------------------------- notes
@router.post("/{incident_id}/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
def add_note(incident_id: int, body: NoteCreate, request: Request, db: Session = Depends(get_db),
             user: User = Depends(require_role(Role.ANALYST))):
    incident = _get_incident(db, incident_id)
    note = IncidentNote(incident_id=incident.id, author_id=user.id, body=body.body)
    db.add(note)
    incident.updated_at = utcnow()
    db.commit()
    audit.record(db, action="incident.note", outcome="success", user=user,
                 target=f"incident:{incident.id}", client_ip=client_ip(request))
    return NoteOut(id=note.id, author=user.username, body=note.body, created_at=note.created_at)


# ---------------------------------------------------------------- evidence
@router.post("/{incident_id}/evidence", response_model=EvidenceOut, status_code=status.HTTP_201_CREATED)
def add_evidence(
    incident_id: int,
    request: Request,
    description: str | None = Form(None, max_length=5000),
    file: UploadFile | None = File(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ANALYST)),
):
    incident = _get_incident(db, incident_id)
    if file is None and not (description or "").strip():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail="Provide a file, a description, or both")

    evidence = Evidence(incident_id=incident.id, uploaded_by_id=user.id, description=description)
    if file is not None:
        try:
            stored = save_upload(file.file, file.filename, allowed_kinds=EVIDENCE_KINDS,
                                 max_bytes=get_settings().max_evidence_bytes, subdir=EVIDENCE_SUBDIR)
        except UploadRejected as exc:
            audit.record(db, action="evidence.upload", outcome="denied", user=user,
                         target=f"incident:{incident.id}", detail=exc.message, client_ip=client_ip(request))
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from None
        evidence.original_name = stored.original_name
        evidence.stored_name = stored.stored_name
        evidence.content_type = stored.content_type
        evidence.size_bytes = stored.size
        evidence.sha256 = stored.sha256

    db.add(evidence)
    incident.updated_at = utcnow()
    db.commit()
    audit.record(db, action="evidence.upload", outcome="success", user=user, target=f"incident:{incident.id}",
                 detail=f"sha256={evidence.sha256}" if evidence.sha256 else "description only",
                 client_ip=client_ip(request))
    return EvidenceOut(
        id=evidence.id, description=evidence.description, original_name=evidence.original_name,
        content_type=evidence.content_type, size_bytes=evidence.size_bytes, sha256=evidence.sha256,
        uploaded_by=user.username, created_at=evidence.created_at, has_file=evidence.stored_name is not None,
    )


@evidence_router.get("/{evidence_id}/download")
def download_evidence(evidence_id: int, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_role(Role.ANALYST))):
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.stored_name is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file not found")
    path = stored_path(EVIDENCE_SUBDIR, evidence.stored_name)
    if not path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file missing from storage")
    audit.record(db, action="evidence.download", outcome="success", user=user,
                 target=f"evidence:{evidence.id}", client_ip=client_ip(request))
    # Always served as a download ("attachment") with a generic type, so the
    # browser never renders or executes uploaded content.
    return FileResponse(path, filename=evidence.original_name, media_type="application/octet-stream")


@assign_router.get("/assignable", response_model=list[AssignableUser])
def assignable_users(db: Session = Depends(get_db), _user: User = Depends(require_role(Role.ANALYST))):
    """Active analysts/admins, for the 'assign incident' dropdown (no sensitive fields)."""
    return db.scalars(select(User).where(User.is_active.is_(True), User.role != Role.VIEWER)
                      .order_by(User.username)).all()
