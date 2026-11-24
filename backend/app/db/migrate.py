"""Bring the database schema up to date with Alembic migrations.

Every entry point (API server start-up, CLI scripts) calls upgrade_database()
before touching the database, so the schema is always current - nobody has
to remember to run `alembic upgrade head` by hand.

Databases created before migrations existed (Phase 3-8 builds used
create_all) have tables but no `alembic_version` table. For those we create
any missing tables and then "stamp" the database as up to date.
"""

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from app import models  # noqa: F401  (registers all tables)
from app.db.session import Base, engine

BACKEND_DIR = Path(__file__).resolve().parents[2]
logger = logging.getLogger("mini_soc.migrate")


def alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


def upgrade_database() -> None:
    cfg = alembic_config()
    with engine.begin() as connection:
        cfg.attributes["connection"] = connection
        tables = set(inspect(connection).get_table_names())
        if tables and "alembic_version" not in tables:
            logger.warning("Existing database without migration history: creating missing tables and stamping.")
            Base.metadata.create_all(bind=connection)
            command.stamp(cfg, "head")
        else:
            command.upgrade(cfg, "head")
