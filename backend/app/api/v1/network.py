"""Network scanning endpoints: scope, profiles, scans, device inventory."""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require_role
from app.db.session import get_db
from app.integrations.nmap.runner import PROFILES
from app.integrations.nmap.scope import ScopeError, ensure_in_scope, parse_target, validate_scope
from app.models import AppSetting, Device, DevicePort, Scan, User
from app.models.enums import Role
from app.schemas.common import Page
from app.schemas.network import DeviceOut, PortOut, ProfileOut, ScanOut, ScanRequest, ScopeOut, ScopeUpdate
from app.services import audit, settings_store
from app.services.scans import execute_scan, has_active_scan

router = APIRouter(tags=["network"])


def _scan_out(db: Session, scan: Scan) -> ScanOut:
    out = ScanOut.model_validate(scan)
    if scan.requested_by_id:
        out.requested_by = db.scalar(select(User.username).where(User.id == scan.requested_by_id))
    return out


# ---------------------------------------------------------------- scope
@router.get("/settings/scan-scope", response_model=ScopeOut)
def get_scope(db: Session = Depends(get_db), _user: User = Depends(require_role(Role.VIEWER))):
    row = db.get(AppSetting, settings_store.SCAN_SCOPE_KEY)
    cidrs = [str(n) for n in settings_store.get_scan_scope(db)]
    updated_by = db.scalar(select(User.username).where(User.id == row.updated_by_id)) if row else None
    return ScopeOut(cidrs=cidrs, is_default=row is None, updated_at=row.updated_at if row else None,
                    updated_by=updated_by)


@router.put("/settings/scan-scope", response_model=ScopeOut)
def update_scope(body: ScopeUpdate, request: Request, db: Session = Depends(get_db),
                 admin: User = Depends(require_role(Role.ADMIN))):
    try:
        networks = validate_scope(body.cidrs, body.allow_public)
    except ScopeError as exc:
        audit.record(db, action="scope.update", outcome="denied", user=admin, detail=str(exc),
                     client_ip=client_ip(request))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None
    cidrs = [str(n) for n in networks]
    settings_store.set_value(db, settings_store.SCAN_SCOPE_KEY, cidrs, admin)
    audit.record(db, action="scope.update", outcome="success", user=admin, target=", ".join(cidrs),
                 detail="public ranges confirmed" if body.allow_public else None, client_ip=client_ip(request))
    return get_scope(db, admin)


# ---------------------------------------------------------------- scans
@router.get("/scans/profiles", response_model=list[ProfileOut])
def list_profiles(_user: User = Depends(require_role(Role.VIEWER))):
    return [ProfileOut(id=p.id, label=p.label, command="nmap " + " ".join(p.args), description=p.description)
            for p in PROFILES.values()]


@router.post("/scans", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def start_scan(body: ScanRequest, request: Request, background: BackgroundTasks,
               db: Session = Depends(get_db), user: User = Depends(require_role(Role.ANALYST))):
    ip = client_ip(request)
    try:
        target = parse_target(body.target)
        ensure_in_scope(target, settings_store.get_scan_scope(db))
    except ScopeError as exc:
        # Refused scans are audited too: attempts to scan outside scope matter.
        audit.record(db, action="scan.request", outcome="denied", user=user, target=body.target[:64],
                     detail=str(exc), client_ip=ip)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from None

    if has_active_scan(db):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Another scan is already running. Wait for it to finish.")

    # Show a single host as "192.168.56.1", not "192.168.56.1/32".
    target_text = str(target.network_address) if target.num_addresses == 1 else str(target)
    scan = Scan(target=target_text, profile=body.profile, requested_by_id=user.id)
    db.add(scan)
    db.commit()
    audit.record(db, action="scan.request", outcome="success", user=user, target=str(target),
                 detail=f"profile={body.profile} scan={scan.id}", client_ip=ip)
    background.add_task(execute_scan, scan.id)  # runs after the response is sent
    return _scan_out(db, scan)


@router.get("/scans", response_model=Page[ScanOut])
def list_scans(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
               db: Session = Depends(get_db), _user: User = Depends(require_role(Role.VIEWER))):
    total = db.scalar(select(func.count()).select_from(Scan)) or 0
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)).all()
    return Page[ScanOut](items=[_scan_out(db, s) for s in scans], total=total)


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), _user: User = Depends(require_role(Role.VIEWER))):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _scan_out(db, scan)


# ---------------------------------------------------------------- devices
@router.get("/devices", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db), _user: User = Depends(require_role(Role.VIEWER))):
    devices = db.scalars(select(Device).order_by(Device.last_seen.desc())).all()
    ports = db.scalars(select(DevicePort).where(DevicePort.state == "open")
                       .order_by(DevicePort.port)).all()
    by_device: dict[int, list[PortOut]] = {}
    for p in ports:
        by_device.setdefault(p.device_id, []).append(PortOut.model_validate(p))
    out = []
    for d in devices:
        item = DeviceOut.model_validate(d)
        item.ports = by_device.get(d.id, [])
        out.append(item)
    return out
