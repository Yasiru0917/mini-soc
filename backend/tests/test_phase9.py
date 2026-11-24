"""Phase 9: security-review fixes and database migrations."""

from sqlalchemy import inspect, text

from app.core.rate_limit import LoginRateLimiter
from app.db.migrate import upgrade_database
from app.db.session import Base, engine
from app.models.enums import Role
from tests.conftest import PASSWORD, login

NEW_PASSWORD = "a-brand-new-passphrase"


def test_change_password_requires_current_and_revokes_other_sessions(client, make_user):
    make_user("alice")
    login(client, "alice")
    old_cookie = client.cookies.get("soc_session")

    bad = client.post("/api/v1/auth/change-password", json={"current_password": "wrong-one-1234",
                                                             "new_password": NEW_PASSWORD})
    assert bad.status_code == 400

    ok = client.post("/api/v1/auth/change-password", json={"current_password": PASSWORD,
                                                            "new_password": NEW_PASSWORD})
    assert ok.status_code == 204
    assert client.get("/api/v1/auth/me").status_code == 200  # this browser stays signed in

    client.cookies.clear()
    client.cookies.set("soc_session", old_cookie, domain="localhost", path="/api")
    assert client.get("/api/v1/auth/me").status_code == 401  # other sessions are signed out
    client.cookies.clear()
    assert login(client, "alice", NEW_PASSWORD).status_code == 200


def test_admin_password_reset(admin_client, make_user):
    target = make_user("bob", Role.ANALYST)
    short = admin_client.post(f"/api/v1/users/{target.id}/reset-password", json={"new_password": "short"})
    assert short.status_code == 422
    ok = admin_client.post(f"/api/v1/users/{target.id}/reset-password", json={"new_password": NEW_PASSWORD})
    assert ok.status_code == 204
    admin_client.cookies.clear()
    assert login(admin_client, "bob", NEW_PASSWORD).status_code == 200


def test_audit_log_is_admin_only_and_records_refused_scans(client, make_user):
    make_user("an", Role.ANALYST)
    make_user("ad", Role.ADMIN)
    login(client, "an")
    client.post("/api/v1/scans", json={"target": "1.1.1.1", "profile": "quick"})
    assert client.get("/api/v1/users/audit-log").status_code == 403
    client.cookies.clear()

    login(client, "ad")
    page = client.get("/api/v1/users/audit-log", params={"action": "scan"}).json()
    assert page["total"] == 1
    entry = page["items"][0]
    assert entry["username"] == "an" and entry["outcome"] == "denied" and entry["target"] == "1.1.1.1"


def test_huge_json_body_rejected(client):
    resp = client.post("/api/v1/auth/login", content=b"{}",
                       headers={"Content-Type": "application/json", "Content-Length": str(50 * 1024 * 1024)})
    assert resp.status_code == 413


def test_rate_limiter_memory_is_bounded(monkeypatch):
    limiter = LoginRateLimiter(max_failures=5, window_seconds=0)  # failures expire immediately
    monkeypatch.setattr(LoginRateLimiter, "MAX_KEYS", 100)
    for i in range(1000):
        limiter.record_failure(f"user:attacker{i}")
    assert len(limiter._failures) <= 102


def test_migrations_build_the_schema_from_scratch():
    Base.metadata.drop_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    upgrade_database()
    tables = set(inspect(engine).get_table_names())
    assert {"users", "alerts", "incidents", "scans", "log_uploads", "ioc_lookups", "alembic_version"} <= tables
    upgrade_database()  # running again is harmless


def test_legacy_database_is_stamped():
    """A database created before migrations existed is adopted, not broken."""
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    Base.metadata.create_all(bind=engine)
    upgrade_database()
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
