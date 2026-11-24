"""Audit log: an append-only record of security-relevant actions.

Who did what, to what, when, from where, and whether it was allowed.
SOC teams rely on audit logs to investigate misuse of the tools themselves.
"""

from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base, UTCDateTime, utcnow


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # Stored separately so the record survives if the user is renamed/deleted,
    # and so failed logins for unknown usernames can be recorded.
    username: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)  # e.g. "auth.login"
    outcome: Mapped[str] = mapped_column(String(16))             # "success" | "failure" | "denied"
    target: Mapped[str | None] = mapped_column(String(255))
    client_ip: Mapped[str | None] = mapped_column(String(45))
    detail: Mapped[str | None] = mapped_column(String(500))
