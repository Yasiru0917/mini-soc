"""Login, logout and "who am I".

Flow:
  1. POST /auth/login with username + password (JSON).
  2. Server checks the rate limit, then the Argon2 hash.
  3. On success it sets the `soc_session` cookie:
       HttpOnly        -> JavaScript cannot read it (protects against XSS theft)
       SameSite=Strict -> browser won't send it on requests from other sites (CSRF)
       Secure          -> HTTPS only (enabled in production)
       Path=/api       -> only sent to API routes
  4. The browser sends the cookie automatically on later /api requests.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import SESSION_COOKIE, client_ip, get_current_user
from app.core.config import get_settings
from app.core.rate_limit import LoginRateLimiter
from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db, utcnow
from app.models import User
from app.schemas.user import LoginRequest, PasswordChange, UserOut
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])

_settings = get_settings()
login_limiter = LoginRateLimiter(_settings.login_max_failures, _settings.login_window_seconds)

# One message for every failure, so attackers can't tell whether a username exists.
_INVALID = "Invalid username or password"


def _set_session_cookie(response: Response, token: str, max_age: int) -> None:
    settings = get_settings()
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure or settings.is_production,
        samesite="strict",
        path="/api",
    )


@router.post("/login", response_model=UserOut)
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    username = body.username.strip().lower()
    limiter_keys = (f"user:{username}", f"ip:{ip}")

    # 1. Rate limit BEFORE checking the password (so blocked guesses cost nothing).
    wait = login_limiter.retry_after(*limiter_keys)
    if wait:
        audit.record(db, action="auth.login", outcome="denied", username=username,
                     client_ip=ip, detail="rate limited")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(wait)},
        )

    # 2. Verify credentials. verify_password(None) still spends time hashing.
    user = db.scalar(select(User).where(User.username == username))
    password_ok = verify_password(body.password, user.password_hash if user else None)

    if not password_ok or user is None or not user.is_active:
        login_limiter.record_failure(*limiter_keys)
        reason = "unknown user" if user is None else ("inactive" if not user.is_active else "bad password")
        audit.record(db, action="auth.login", outcome="failure", user=user, username=username,
                     client_ip=ip, detail=reason)  # reason is stored server-side only
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID)

    # 3. Success: clear failures, issue token, record it.
    login_limiter.reset(*limiter_keys)
    user.last_login_at = utcnow()
    db.commit()

    token, max_age = create_access_token(user.id, user.role.value, user.token_version)
    _set_session_cookie(response, token, max_age)
    audit.record(db, action="auth.login", outcome="success", user=user, client_ip=ip)
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response,
           user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Bumping token_version invalidates this token (and any copy of it),
    # even though JWTs can't be "deleted" from the server.
    user.token_version += 1
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/api")
    audit.record(db, action="auth.logout", outcome="success", user=user, client_ip=client_ip(request))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    """The frontend calls this to learn who is signed in (it can't read the cookie)."""
    return user


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(body: PasswordChange, request: Request, response: Response,
                    user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Self-service password change. Requires the CURRENT password, so someone
    who finds an unlocked, signed-in browser can't lock the owner out."""
    ip = client_ip(request)
    if not verify_password(body.current_password, user.password_hash):
        audit.record(db, action="auth.change_password", outcome="failure", user=user, client_ip=ip)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be different")
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1  # sign out every other session
    db.commit()
    # Keep THIS browser signed in with a fresh token.
    token, max_age = create_access_token(user.id, user.role.value, user.token_version)
    _set_session_cookie(response, token, max_age)
    audit.record(db, action="auth.change_password", outcome="success", user=user, client_ip=ip)
