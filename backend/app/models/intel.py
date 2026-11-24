"""Threat-intel lookup cache and generated-report history."""

from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base, UTCDateTime, utcnow


class IocLookup(Base):
    """One provider's answer about one indicator. Reused until it expires (saves API quota)."""

    __tablename__ = "ioc_lookups"

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator: Mapped[str] = mapped_column(String(255), index=True)
    indicator_type: Mapped[str] = mapped_column(String(16))
    provider: Mapped[str] = mapped_column(String(32))
    verdict: Mapped[str] = mapped_column(String(16))
    result_json: Mapped[str] = mapped_column(Text)
    queried_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    queried_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class GeneratedReport(Base):
    __tablename__ = "generated_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))  # incident_pdf | incident_csv | alerts_csv
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    filename: Mapped[str] = mapped_column(String(200))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    generated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    generated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
