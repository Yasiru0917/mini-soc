"""Incidents, investigation notes and evidence."""

from datetime import datetime

from sqlalchemy import BigInteger, Enum, ForeignKey, String, Text
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
    # True if the incident was built from demo alerts ("tainted" by simulated data).
    is_simulated: Mapped[bool] = mapped_column(default=False)

    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    resolution: Mapped[str | None] = mapped_column(Text)
    recommendations: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class IncidentNote(Base):
    """A timestamped investigation note. Notes are append-only (no edit/delete),
    so the investigation history can't be quietly rewritten."""

    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Evidence(Base):
    """A piece of evidence: an uploaded file (with SHA-256) and/or a description."""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    uploaded_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    description: Mapped[str | None] = mapped_column(Text)

    # File fields are empty for description-only evidence (e.g. "suspicious IP 203.0.113.9").
    original_name: Mapped[str | None] = mapped_column(String(200))
    stored_name: Mapped[str | None] = mapped_column(String(64))
    content_type: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
