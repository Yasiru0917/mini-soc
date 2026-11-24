"""Log analysis endpoints: upload, list, detail, parsed events, rule catalogue."""

import json
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require_role
from app.core.config import get_settings
from app.db.session import get_db
from app.detection.rules import RULES
from app.models import Alert, LogUpload, ParsedEvent, User
from app.models.enums import Role
from app.schemas.alert import AlertOut
from app.schemas.common import Page
from app.services import audit
from app.services.log_analysis import AnalysisError, analyse
from app.services.uploads import UploadRejected, save_upload

router = APIRouter(prefix="/logs", tags=["logs"])


class UploadOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    original_name: str
    sha256: str
    size_bytes: int
    log_type: str
    status: str
    lines_total: int
    events_parsed: int
    lines_skipped: int
    alerts_raised: int
    error: str | None
    uploaded_by: str | None = None
    created_at: datetime


class UploadDetail(UploadOut):
    summary: dict | None = None
    alerts: list[AlertOut] = []


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    line_no: int
    timestamp: datetime | None
    event_type: str
    src_ip: str | None
    user: str | None
    detail: str | None


def _out(db: Session, u: LogUpload, cls=UploadOut):
    item = cls.model_validate(u)
    if u.uploaded_by_id:
        item.uploaded_by = db.scalar(select(User.username).where(User.id == u.uploaded_by_id))
    return item


@router.get("/rules")
def list_rules(_user: User = Depends(require_role(Role.VIEWER))) -> list[dict]:
    """The real rule catalogue, straight from the detection code."""
    return [{"id": r.id, "name": r.name, "logic": r.logic, "mitre": r.mitre, "severity": r.severity,
             "applies_to": r.applies_to} for r in RULES.values()]


@router.post("/upload", response_model=UploadDetail, status_code=status.HTTP_201_CREATED)
def upload_log(
    request: Request,
    file: UploadFile = File(...),
    log_type: Literal["auto", "auth", "access", "jsonl", "pcap"] = Form("auto"),
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ANALYST)),
):
    s = get_settings()
    ip = client_ip(request)
    is_pcap_name = (file.filename or "").lower().endswith((".pcap", ".pcapng", ".cap"))
    try:
        stored = save_upload(file.file, file.filename, allowed_kinds={"text", "pcap"},
                             max_bytes=s.max_pcap_bytes if is_pcap_name else s.max_log_bytes, subdir="logs")
    except UploadRejected as exc:
        audit.record(db, action="log.upload", outcome="denied", user=user, target=(file.filename or "")[:200],
                     detail=exc.message, client_ip=ip)
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from None

    # Same file analysed before? Don't create duplicate alerts.
    previous = db.scalar(select(LogUpload).where(LogUpload.sha256 == stored.sha256,
                                                 LogUpload.status == "processed"))
    if previous:
        stored.path.unlink(missing_ok=True)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"This exact file was already analysed (upload #{previous.id}).")

    try:
        upload = analyse(db, stored, log_type, user)
    except AnalysisError as exc:
        db.rollback()
        stored.path.unlink(missing_ok=True)
        audit.record(db, action="log.upload", outcome="failure", user=user, target=stored.original_name,
                     detail=str(exc), client_ip=ip)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None

    audit.record(db, action="log.upload", outcome="success", user=user, target=stored.original_name,
                 detail=(f"upload={upload.id} type={upload.log_type} sha256={upload.sha256} "
                         f"alerts={upload.alerts_raised}"),
                 client_ip=ip)
    return get_upload(upload.id, db, user)


@router.get("", response_model=Page[UploadOut])
def list_uploads(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
                 db: Session = Depends(get_db), _user: User = Depends(require_role(Role.VIEWER))):
    total = db.scalar(select(func.count()).select_from(LogUpload)) or 0
    rows = db.scalars(select(LogUpload).order_by(LogUpload.created_at.desc()).limit(limit).offset(offset)).all()
    return Page[UploadOut](items=[_out(db, u) for u in rows], total=total)


@router.get("/{upload_id}", response_model=UploadDetail)
def get_upload(upload_id: int, db: Session = Depends(get_db), _user: User = Depends(require_role(Role.VIEWER))):
    upload = db.get(LogUpload, upload_id)
    if upload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Upload not found")
    detail = _out(db, upload, UploadDetail)
    detail.summary = json.loads(upload.summary_json) if upload.summary_json else None
    prefix = f"upload:{upload.id}"
    alerts = db.scalars(select(Alert).where((Alert.raw_reference == prefix) | Alert.raw_reference.like(prefix + ":%"))
                        .order_by(Alert.severity)).all()
    detail.alerts = [AlertOut.model_validate(a) for a in alerts]
    return detail


@router.get("/{upload_id}/events", response_model=Page[EventOut])
def list_events(upload_id: int, event_type: str | None = Query(None, max_length=32),
                src_ip: str | None = Query(None, max_length=45),
                limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                db: Session = Depends(get_db), _user: User = Depends(require_role(Role.VIEWER))):
    filters = [ParsedEvent.upload_id == upload_id]
    if event_type:
        filters.append(ParsedEvent.event_type == event_type)
    if src_ip:
        filters.append(ParsedEvent.src_ip == src_ip)
    total = db.scalar(select(func.count()).select_from(ParsedEvent).where(*filters)) or 0
    rows = db.scalars(select(ParsedEvent).where(*filters).order_by(ParsedEvent.line_no)
                      .limit(limit).offset(offset)).all()
    return Page[EventOut](items=[EventOut.model_validate(r) for r in rows], total=total)
