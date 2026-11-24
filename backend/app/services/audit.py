"""Write entries to the audit log."""

import logging

from sqlalchemy.orm import Session

from app.models import AuditLog, User

logger = logging.getLogger("mini_soc.audit")


def _clean(value: str | None, max_len: int) -> str | None:
    """Remove control characters (e.g. newlines) and cap length.

    Usernames in failed logins come straight from an attacker. Without this,
    someone could type "x\\nadmin login success" and forge a fake log line
    ("log injection").
    """
    if value is None:
        return None
    return "".join(ch if ch.isprintable() else "?" for ch in value)[:max_len]


def record(
    db: Session,
    *,
    action: str,
    outcome: str,
    user: User | None = None,
    username: str | None = None,
    target: str | None = None,
    client_ip: str | None = None,
    detail: str | None = None,
) -> None:
    """Add an audit entry and commit it.

    The audit entry is committed on its own so that it is saved even if the
    request is about to be rejected (e.g. a failed login).
    """
    entry = AuditLog(
        user_id=user.id if user else None,
        username=_clean(user.username if user else username, 64),
        action=action,
        outcome=outcome,
        target=_clean(target, 255),
        client_ip=_clean(client_ip, 45),
        detail=_clean(detail, 500),
    )
    db.add(entry)
    db.commit()
    # Also write to the server console/log file. Never log passwords or tokens.
    logger.info("%s %s user=%s ip=%s target=%s", action, outcome, entry.username, client_ip, target)
