"""Security alerts. Endpoints to manage them arrive in Phase 4.

Provenance fields (`source`, `is_simulated`, `detection_rule_id`,
`raw_reference`) record exactly what produced each alert, so nothing can be
presented as a real detection unless a real mechanism created it.
"""

from datetime import datetime

from sqlalchemy import Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base, UTCDateTime, utcnow
from app.models.enums import AlertSource, AlertStatus, Severity


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, native_enum=False, length=16), index=True)
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, native_enum=False, length=16), default=AlertStatus.NEW, index=True
    )

    # --- provenance ---
    source: Mapped[AlertSource] = mapped_column(Enum(AlertSource, native_enum=False, length=16), index=True)
    is_simulated: Mapped[bool] = mapped_column(default=False, index=True)
    detection_rule_id: Mapped[str | None] = mapped_column(String(32))
    raw_reference: Mapped[str | None] = mapped_column(String(255))

    # --- network context (IPv6 max textual length is 45) ---
    src_ip: Mapped[str | None] = mapped_column(String(45))
    dst_ip: Mapped[str | None] = mapped_column(String(45))

    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))

    detected_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
