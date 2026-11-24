"""Alembic environment: connects migrations to the Mini SOC models and settings.

Two ways this runs:
  * CLI:  `alembic revision --autogenerate -m "..."` / `alembic upgrade head`
  * App:  app/db/migrate.py calls Alembic programmatically at startup and
          passes an open connection via config.attributes["connection"].
"""

from alembic import context
from sqlalchemy import engine_from_config, pool

from app import models  # noqa: F401  (registers every table on Base.metadata)
from app.core.config import get_settings
from app.db.session import Base

config = context.config
target_metadata = Base.metadata


def _configure(connection=None, url=None) -> None:
    context.configure(
        connection=connection,
        url=url,
        target_metadata=target_metadata,
        # SQLite can't ALTER most things in place; "batch" mode recreates the
        # table behind the scenes so column changes still work.
        render_as_batch=True,
        compare_type=True,
        literal_binds=url is not None,
    )


def run_migrations_offline() -> None:
    """Generate SQL without a database connection (`alembic upgrade head --sql`)."""
    _configure(url=get_settings().database_url)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:  # called from the app
        _configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()
        return

    engine = engine_from_config({"sqlalchemy.url": get_settings().database_url}, prefix="sqlalchemy.",
                                poolclass=pool.NullPool)
    with engine.connect() as conn:
        _configure(connection=conn)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
