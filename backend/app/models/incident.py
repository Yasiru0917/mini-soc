"""Incidents. Notes, evidence and endpoints arrive in Phase 4."""

from datetime import datetime

from sqlalchemy import Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base, UTCDateTime, utcnow
from app.models.enums import IncidentStatus, Severity


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, native_enum=False, length=16))
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, native_enum=False, length=16), default=IncidentStatus.NEW, index=True
    )
    is_simulated: Mapped[bool] = mapped_column(default=False)

    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    resolution: Mapped[str | None] = mapped_column(Text)
    recommendations: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
