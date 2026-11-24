"""Authentication tests: hashing, cookie flags, rate limiting, revocation."""

from sqlalchemy import select

from app.models import AuditLog, User
from app.models.enums import Role
from tests.conftest import PASSWORD, login


def test_password_is_stored_as_argon2_hash(make_user, db):
    make_user("alice")
    stored = db.scalar(select(User).where(User.username == "alice")).password_hash
    assert PASSWORD not in stored
    assert stored.startswith("$argon2id$")


def test_login_success_sets_secure_cookie(client, make_user):
    make_user("alice", Role.ANALYST)
    resp = login(client, "alice")
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "alice" and body["role"] == "analyst"
    assert "password_hash" not in body and "token_version" not in body

    cookie = resp.headers["set-cookie"].lower()
    assert "soc_session=" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/api" in cookie


def test_login_is_case_insensitive_for_username(client, make_user):
    make_user("alice")
    assert login(client, "ALICE").status_code == 200


def test_wrong_password_and_unknown_user_give_same_error(client, make_user):
    make_user("alice")
    wrong = login(client, "alice", "wrong-password-123")
    unknown = login(client, "nobody", "wrong-password-123")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": "Invalid username or password"}


def test_inactive_user_cannot_login(client, make_user):
    make_user("bob", active=False)
    assert login(client, "bob").status_code == 401


def test_rate_limit_after_five_failures(client, make_user):
    make_user("alice")
    for _ in range(5):
        assert login(client, "alice", "bad-password-xyz").status_code == 401
    # Even the CORRECT password is now refused until the window passes.
    blocked = login(client, "alice")
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0


def test_me_requires_authentication(client):
    assert client.get("/api/v1/auth/me").status_code == 401


def test_me_returns_current_user(client, make_user):
    make_user("alice")
    login(client, "alice")
    assert client.get("/api/v1/auth/me").json()["username"] == "alice"


def test_forged_token_is_rejected(client, make_user):
    """An attacker who doesn't know SECRET_KEY can't mint a valid admin token."""
    import time

    import jwt

    user = make_user("alice")
    now = int(time.time())
    forged = jwt.encode(
        {"sub": str(user.id), "role": "admin", "ver": 0, "iat": now, "exp": now + 600},
        "attacker-guessed-secret-key-0123456789",
        algorithm="HS256",
    )
    client.cookies.clear()
    client.cookies.set("soc_session", forged, domain="localhost", path="/api")
    assert client.get("/api/v1/auth/me").status_code == 401


def test_unsigned_alg_none_token_is_rejected(client, make_user):
    """Classic JWT attack: alg=none (no signature). We only accept HS256."""
    import base64
    import json

    user = make_user("alice")

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': str(user.id), 'ver': 0})}."
    client.cookies.clear()
    client.cookies.set("soc_session", token, domain="localhost", path="/api")
    assert client.get("/api/v1/auth/me").status_code == 401


def test_logout_revokes_token_even_if_reused(client, make_user):
    make_user("alice")
    login(client, "alice")
    stolen = client.cookies.get("soc_session")

    assert client.post("/api/v1/auth/logout").status_code == 204
    # An attacker replaying the old token must be rejected.
    client.cookies.clear()
    client.cookies.set("soc_session", stolen, domain="localhost", path="/api")
    assert client.get("/api/v1/auth/me").status_code == 401


def test_logins_are_audited(client, make_user, db):
    make_user("alice")
    login(client, "alice", "bad-password-xyz")
    login(client, "alice")
    outcomes = [e.outcome for e in db.scalars(select(AuditLog).where(AuditLog.action == "auth.login"))]
    assert outcomes == ["failure", "success"]


def test_audit_strips_newlines_from_attacker_usernames(client, db):
    login(client, "evil\nauth.login success admin", "whatever-password")
    entry = db.scalar(select(AuditLog))
    assert "\n" not in entry.username
