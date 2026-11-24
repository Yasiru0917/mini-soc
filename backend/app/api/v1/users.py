"""Basic user management (admin only)."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require_role
from app.core.security import hash_password
from app.db.session import get_db
from app.models import AuditLog, User
from app.models.enums import Role
from app.schemas.common import Page
from app.schemas.user import PasswordReset, UserCreate, UserOut, UserUpdate
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    username: str | None
    action: str
    outcome: str
    target: str | None
    client_ip: str | None
    detail: str | None

admin_only = require_role(Role.ADMIN)


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _admin: User = Depends(admin_only)):
    return db.scalars(select(User).order_by(User.username)).all()


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, request: Request,
                db: Session = Depends(get_db), admin: User = Depends(admin_only)):
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")

    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.commit()
    audit.record(db, action="user.create", outcome="success", user=admin,
                 target=f"{user.username} ({user.role})", client_ip=client_ip(request))
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserUpdate, request: Request,
                db: Session = Depends(get_db), admin: User = Depends(admin_only)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent an admin from locking themselves (and possibly everyone) out.
    if user.id == admin.id and (body.is_active is False or (body.role and body.role != Role.ADMIN)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="You cannot demote or deactivate your own account")

    changes = []
    if body.role is not None and body.role != user.role:
        changes.append(f"role {user.role}->{body.role}")
        user.role = body.role
    if body.is_active is not None and body.is_active != user.is_active:
        changes.append(f"active {user.is_active}->{body.is_active}")
        user.is_active = body.is_active

    if changes:
        # Force the user to sign in again so the change applies everywhere.
        user.token_version += 1
        db.commit()
        audit.record(db, action="user.update", outcome="success", user=admin,
                     target=user.username, detail="; ".join(changes), client_ip=client_ip(request))
    return user


@router.post("/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(user_id: int, body: PasswordReset, request: Request,
                   db: Session = Depends(get_db), admin: User = Depends(admin_only)):
    """Admin sets a new password for someone who forgot theirs (signs them out everywhere)."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Use 'Change my password' for your own account")
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    db.commit()
    audit.record(db, action="user.reset_password", outcome="success", user=admin, target=user.username,
                 client_ip=client_ip(request))


@router.get("/audit-log", response_model=Page[AuditOut], tags=["audit"])
def audit_log(action: str | None = Query(None, max_length=64), outcome: str | None = Query(None, max_length=16),
              limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
              db: Session = Depends(get_db), _admin: User = Depends(admin_only)):
    """Security-relevant actions: logins, scans (incl. refused), uploads, lookups, changes."""
    filters = []
    if action:
        filters.append(AuditLog.action.startswith(action))
    if outcome:
        filters.append(AuditLog.outcome == outcome)
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*filters)) or 0
    rows = db.scalars(select(AuditLog).where(*filters).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
                      .limit(limit).offset(offset)).all()
    return Page[AuditOut](items=[AuditOut.model_validate(r) for r in rows], total=total)
