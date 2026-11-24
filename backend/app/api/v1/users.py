"""Basic user management (admin only)."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require_role
from app.core.security import hash_password
from app.db.session import get_db
from app.models import User
from app.models.enums import Role
from app.schemas.user import UserCreate, UserOut, UserUpdate
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])

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
