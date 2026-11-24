"""Database connection.

- `engine` is the connection to SQLite.
- `SessionLocal` creates a short-lived "session" (unit of work) per request.
- `get_db` is a FastAPI dependency: it opens a session for one request and
  always closes it afterwards, even if the request fails.
"""

from collections.abc import Iterator
from datetime import UTC, datetime

from sqlalchemy import DateTime, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator

from app.core.config import get_settings


class Base(DeclarativeBase):
    """Parent class for all ORM models."""


def utcnow() -> datetime:
    """Timezone-aware UTC 'now'. All timestamps are stored in UTC."""
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """A DateTime column that is always UTC.

    SQLite has no time-zone support: it would hand datetimes back "naive"
    (no zone), and the API would then send ambiguous times to the browser.
    This type converts to UTC on the way in and re-attaches UTC on the way out.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            if value.tzinfo is None:
                raise ValueError("Naive datetime given; use timezone-aware UTC datetimes")
            value = value.astimezone(UTC).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        return value.replace(tzinfo=UTC) if value is not None else None


def _make_engine(url: str):
    connect_args = {}
    if url.startswith("sqlite"):
        # FastAPI may use a different thread for each request.
        connect_args["check_same_thread"] = False
    engine = create_engine(url, connect_args=connect_args)

    if url.startswith("sqlite"):
        # SQLite ignores foreign keys unless this is switched on per connection.
        @event.listens_for(engine, "connect")
        def _enable_foreign_keys(dbapi_conn, _record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


engine = _make_engine(get_settings().database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
