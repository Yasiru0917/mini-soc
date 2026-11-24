"""Application settings.

All configuration comes from environment variables or the `backend/.env` file.
Nothing secret is hard-coded. pydantic-settings validates every value at
startup, so a missing or weak SECRET_KEY stops the app immediately with a
clear error, instead of silently running insecurely.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/ folder: used to resolve relative paths no matter where you start the server from
BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Required. min_length makes a short/guessable key a startup error.
    secret_key: str = Field(min_length=32)

    app_env: Literal["development", "production"] = "development"
    database_url: str = "sqlite:///./data/soc.db"
    access_token_minutes: int = Field(default=30, ge=5, le=24 * 60)
    cookie_secure: bool = False
    allowed_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    # Login rate limiting: after N failures within the window, block further attempts.
    login_max_failures: int = 5
    login_window_seconds: int = 15 * 60

    @field_validator("database_url")
    @classmethod
    def resolve_sqlite_path(cls, value: str) -> str:
        """Turn `sqlite:///./data/soc.db` into an absolute path under backend/."""
        prefix = "sqlite:///"
        if value.startswith(prefix) and not value.startswith(prefix + "/"):
            relative = value.removeprefix(prefix)
            if relative != ":memory:" and not Path(relative).is_absolute():
                db_path = (BACKEND_DIR / relative).resolve()
                db_path.parent.mkdir(parents=True, exist_ok=True)
                return f"{prefix}{db_path.as_posix()}"
        return value

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    """Load settings once and reuse them (cached)."""
    return Settings()
