"""Role-based access control, user management, CSRF origin check, headers."""

from app.models.enums import Role
from tests.conftest import PASSWORD, login


def test_health_is_public_and_reports_db(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok" and resp.json()["database"] == "ok"


def test_security_headers_present(client):
    headers = client.get("/api/v1/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in headers["content-security-policy"]


def test_dashboard_requires_login(client):
    assert client.get("/api/v1/dashboard/summary").status_code == 401


def test_dashboard_empty_database_gives_real_zeros(client, make_user):
    make_user("viewer1", Role.VIEWER)
    login(client, "viewer1")
    data = client.get("/api/v1/dashboard/summary").json()
    assert data["alerts"]["total"] == 0
    assert data["alerts"]["by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert data["incidents"]["open"] == 0
    assert data["recent_alerts"] == []


def test_viewer_cannot_manage_users(client, make_user):
    make_user("viewer1", Role.VIEWER)
    login(client, "viewer1")
    assert client.get("/api/v1/users").status_code == 403


def test_analyst_cannot_manage_users(client, make_user):
    make_user("analyst1", Role.ANALYST)
    login(client, "analyst1")
    resp = client.post("/api/v1/users", json={"username": "x1x", "password": "a" * 12, "role": "admin"})
    assert resp.status_code == 403


def test_admin_creates_user_with_validation(client, make_user):
    make_user("root", Role.ADMIN)
    login(client, "root")

    weak = client.post("/api/v1/users", json={"username": "newbie", "password": "short", "role": "analyst"})
    assert weak.status_code == 422

    bad_name = client.post("/api/v1/users", json={"username": "a b<script>", "password": "x" * 12})
    assert bad_name.status_code == 422

    ok = client.post("/api/v1/users", json={"username": "NewBie", "password": "x" * 12, "role": "analyst"})
    assert ok.status_code == 201 and ok.json()["username"] == "newbie"

    dup = client.post("/api/v1/users", json={"username": "newbie", "password": "y" * 12})
    assert dup.status_code == 409


def test_admin_cannot_demote_self(client, make_user):
    admin = make_user("root", Role.ADMIN)
    login(client, "root")
    resp = client.patch(f"/api/v1/users/{admin.id}", json={"role": "viewer"})
    assert resp.status_code == 400


def test_demotion_takes_effect_immediately(client, make_user):
    """Role is read from the DB on each request; a changed role also revokes old sessions."""
    make_user("root", Role.ADMIN)
    target = make_user("bob", Role.ANALYST)

    login(client, "bob")
    bob_cookie = client.cookies.get("soc_session")
    client.cookies.clear()

    login(client, "root")
    client.patch(f"/api/v1/users/{target.id}", json={"role": "viewer"})
    client.cookies.clear()

    client.cookies.set("soc_session", bob_cookie, domain="localhost", path="/api")
    assert client.get("/api/v1/auth/me").status_code == 401  # must sign in again


def test_cross_site_post_is_blocked(client, make_user):
    make_user("alice")
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "irrelevant-pass"},
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403


def test_same_site_origin_is_allowed(client, make_user):
    make_user("alice")
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": PASSWORD},
        headers={"Origin": "http://localhost:5173"},
    )
    assert resp.status_code == 200
