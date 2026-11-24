"""Bring the database schema up to date.

Every entry point (the API server, CLI scripts) calls upgrade_database()
before touching the database, so the schema is always current.
(Phase 9 replaces this body with Alembic migrations.)
"""

from app import models  # noqa: F401  (registers all tables)
from app.db.session import Base, engine


def upgrade_database() -> None:
    Base.metadata.create_all(bind=engine)
