"""Reusable FastAPI dependencies: "who is calling?" and "are they allowed?".

An endpoint declares what it needs, e.g.

    def delete_thing(user: User = Depends(require_role(Role.ADMIN))): ...

and FastAPI runs these checks before the endpoint body. If a check fails,
the endpoint never runs.
"""

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models import User
from app.models.enums import ROLE_LEVEL, Role

SESSION_COOKIE = "soc_session"

_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
)


def client_ip(request: Request) -> str | None:
    # Uvicorn already replaces this with the X-Forwarded-For value when the
    # request comes through a trusted local proxy (the Vite dev server).
    return request.client.host if request.client else None


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Return the signed-in user, or reject the request with 401."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise _UNAUTHENTICATED

    claims = decode_access_token(token)  # checks signature and expiry
    if claims is None:
        raise _UNAUTHENTICATED

    try:
        user_id = int(claims["sub"])
    except (TypeError, ValueError):
        raise _UNAUTHENTICATED from None

    user = db.get(User, user_id)
    # Reject if the account was deleted/disabled, or the token was revoked
    # (logout or role change bumps token_version).
    if user is None or not user.is_active or claims.get("ver") != user.token_version:
        raise _UNAUTHENTICATED
    return user


def require_role(minimum: Role) -> Callable[..., User]:
    """Allow `minimum` role and anything above it (admin > analyst > viewer).

    The role is read from the DATABASE, not from the token, so demoting a
    user takes effect immediately.
    """

    def checker(user: User = Depends(get_current_user)) -> User:
        if ROLE_LEVEL[user.role] < ROLE_LEVEL[minimum]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return checker
