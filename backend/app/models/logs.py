"""Uploaded log files / packet captures and the events parsed from them."""

from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base, UTCDateTime, utcnow


class LogUpload(Base):
    __tablename__ = "log_uploads"

    id: Mapped[int] = mapped_column(primary_key=True)
    original_name: Mapped[str] = mapped_column(String(200))
    stored_name: Mapped[str] = mapped_column(String(64))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    log_type: Mapped[str] = mapped_column(String(16))  # auth | access | jsonl | pcap
    status: Mapped[str] = mapped_column(String(16))    # processed | failed
    lines_total: Mapped[int] = mapped_column(Integer, default=0)
    events_parsed: Mapped[int] = mapped_column(Integer, default=0)
    lines_skipped: Mapped[int] = mapped_column(Integer, default=0)
    alerts_raised: Mapped[int] = mapped_column(Integer, default=0)
    summary_json: Mapped[str | None] = mapped_column(Text)  # rule hits / pcap statistics
    error: Mapped[str | None] = mapped_column(Text)
    uploaded_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)


class ParsedEvent(Base):
    """One recognised line from an uploaded text log (for browsing / evidence)."""

    __tablename__ = "log_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("log_uploads.id", ondelete="CASCADE"), index=True)
    line_no: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime())
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    user: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(String(600))
