"""User accounts."""

from datetime import datetime

from sqlalchemy import Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base, UTCDateTime, utcnow
from app.models.enums import Role


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    # Argon2id hash - never the password itself.
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False, length=16), default=Role.VIEWER)
    is_active: Mapped[bool] = mapped_column(default=True)
    # Incremented on logout / password change / deactivation. Tokens carrying
    # an older version are rejected, which is how we "revoke" JWTs.
    token_version: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
