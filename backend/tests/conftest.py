"""Shared test setup.

Tests never touch your real database: before the app is imported we point
DATABASE_URL at a temporary file and set a throwaway SECRET_KEY.
Each test starts with empty tables.
"""

import os
import tempfile
from pathlib import Path

_tmp_dir = tempfile.mkdtemp(prefix="minisoc-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_tmp_dir, 'test.db').as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-key-that-is-long-enough-for-hs256"
os.environ["APP_ENV"] = "development"
os.environ["DATA_DIR"] = str(Path(_tmp_dir, "data"))
# Integrations are off in tests unless a test configures them explicitly.
for _var in ("WAZUH_API_URL", "WAZUH_INDEXER_URL", "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "OTX_API_KEY"):
    os.environ[_var] = ""

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.api.v1.auth import login_limiter  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.session import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import User  # noqa: E402
from app.models.enums import Role  # noqa: E402

PASSWORD = "correct-horse-battery"


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    login_limiter._failures.clear()
    yield


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture
def client():
    # base_url uses http://localhost so the cookie (Path=/api) is stored and resent.
    with TestClient(app, base_url="http://localhost") as c:
        yield c


@pytest.fixture
def make_user(db):
    def _make(username: str, role: Role = Role.VIEWER, active: bool = True) -> User:
        user = User(username=username, password_hash=hash_password(PASSWORD), role=role, is_active=active)
        db.add(user)
        db.commit()
        return user

    return _make


def login(client: TestClient, username: str, password: str = PASSWORD):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


@pytest.fixture
def analyst_client(client, make_user):
    """A client already signed in as an analyst."""
    make_user("analyst1", Role.ANALYST)
    assert login(client, "analyst1").status_code == 200
    return client


@pytest.fixture
def admin_client(client, make_user):
    make_user("admin1", Role.ADMIN)
    assert login(client, "admin1").status_code == 200
    return client
