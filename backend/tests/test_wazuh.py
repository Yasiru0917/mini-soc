"""Phase 7: Wazuh integration against a simulated Wazuh server (httpx.MockTransport).

No real Wazuh server is needed: the fake transport answers exactly like the
documented Wazuh server API (/security/user/authenticate, /manager/info,
/agents) and the indexer's /wazuh-alerts-*/_search endpoint.
"""

import json

import httpx
import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.integrations.wazuh.client import WazuhClient
from app.models import Alert
from app.services import wazuh_sync

API, INDEXER = "https://192.168.56.105:55000", "https://192.168.56.105:9200"

HITS = [
    {"_id": "doc-1", "_source": {
        "timestamp": "2026-11-24T10:00:00.000+0000", "location": "/var/log/auth.log",
        "rule": {"id": "5712", "level": 10, "description": "sshd: brute force trying to get access to the system.",
                 "groups": ["syslog", "sshd", "authentication_failures"], "mitre": {"id": ["T1110"]}},
        "agent": {"id": "001", "name": "metasploitable", "ip": "192.168.56.101"},
        "data": {"srcip": "192.168.56.20"}, "full_log": "Failed password for root from 192.168.56.20"}},
    {"_id": "doc-2", "_source": {
        "timestamp": "2026-11-24T10:05:00.000+0000",
        "rule": {"id": "550", "level": 7, "description": "Integrity checksum changed."},
        "agent": {"id": "002", "name": "win-lab", "ip": "not-an-ip"}, "data": {}}},
]


def fake_wazuh(password_ok=True, calls=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append((request.method, request.url.path))
        path = request.url.path
        if path == "/security/user/authenticate":
            if not password_ok:
                return httpx.Response(401, json={"title": "Unauthorized"})
            return httpx.Response(200, json={"data": {"token": "jwt-token"}})
        if path in ("/manager/info", "/agents"):
            assert request.headers["authorization"] == "Bearer jwt-token"
            items = [{"version": "v4.14.10"}] if path == "/manager/info" else [
                {"id": "000", "name": "wazuh-server", "status": "active"},
                {"id": "001", "name": "metasploitable", "ip": "192.168.56.101", "status": "active"}]
            return httpx.Response(200, json={"data": {"affected_items": items}})
        if path == "/wazuh-alerts-*/_search":
            body = json.loads(request.content)
            assert body["query"]["bool"]["filter"][0] == {"range": {"rule.level": {"gte": 7}}}
            return httpx.Response(200, json={"hits": {"hits": HITS}})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


@pytest.fixture
def wazuh_settings(monkeypatch):
    s = get_settings().model_copy(update={
        "wazuh_api_url": API, "wazuh_api_user": "wazuh-wui", "wazuh_api_password": "secret",
        "wazuh_indexer_url": INDEXER, "wazuh_indexer_user": "admin", "wazuh_indexer_password": "secret",
    })
    monkeypatch.setattr("app.api.v1.wazuh.get_settings", lambda: s)
    monkeypatch.setattr(wazuh_sync, "get_settings", lambda: s)
    return s


def use_fake(monkeypatch, **kwargs):
    monkeypatch.setattr(wazuh_sync, "client_factory", lambda s: WazuhClient(s, transport=fake_wazuh(**kwargs)))


def test_severity_mapping():
    assert [wazuh_sync.level_to_severity(n) for n in (15, 12, 11, 10, 9, 7, 6, 4, 3, 0)] == [
        "critical", "critical", "high", "high", "medium", "medium", "low", "low", "info", "info"]


def test_status_not_configured(analyst_client):
    body = analyst_client.get("/api/v1/wazuh/status").json()
    assert body["configured"] is False and body["reachable"] is False and "Not configured" in body["error"]


def test_status_connected(analyst_client, wazuh_settings, monkeypatch):
    use_fake(monkeypatch)
    body = analyst_client.get("/api/v1/wazuh/status").json()
    assert body["reachable"] is True and body["manager_version"] == "v4.14.10" and body["agents_total"] == 2
    assert "secret" not in json.dumps(body)  # credentials never leave the server


def test_bad_password_gives_clear_error(analyst_client, wazuh_settings, monkeypatch):
    use_fake(monkeypatch, password_ok=False)
    body = analyst_client.get("/api/v1/wazuh/status").json()
    assert body["reachable"] is False and "authentication failed" in body["error"]


def test_unreachable_server(analyst_client, wazuh_settings, monkeypatch):
    def refuse(request):
        raise httpx.ConnectError("connection refused", request=request)
    monkeypatch.setattr(wazuh_sync, "client_factory", lambda s: WazuhClient(s, transport=httpx.MockTransport(refuse)))
    body = analyst_client.get("/api/v1/wazuh/status").json()
    assert body["reachable"] is False and "cannot connect" in body["error"]


def test_sync_imports_alerts_once(analyst_client, wazuh_settings, monkeypatch, db):
    use_fake(monkeypatch)
    first = analyst_client.post("/api/v1/wazuh/sync").json()
    assert first["fetched"] == 2 and first["created"] == 2
    second = analyst_client.post("/api/v1/wazuh/sync").json()
    assert second["created"] == 0 and second["duplicates"] == 2

    alerts = {a.raw_reference: a for a in db.scalars(select(Alert))}
    brute = alerts["wazuh:doc-1"]
    assert brute.source == "wazuh" and brute.severity == "high" and brute.detection_rule_id == "WZ-5712"
    assert brute.src_ip == "192.168.56.20" and brute.dst_ip == "192.168.56.101"
    assert "T1110" in brute.description and brute.detected_at.isoformat().startswith("2026-11-24T10:00")
    assert alerts["wazuh:doc-2"].dst_ip is None  # invalid IP from Wazuh is dropped, not stored


def test_viewer_cannot_sync(client, make_user):
    from app.models.enums import Role
    from tests.conftest import login
    make_user("v", Role.VIEWER)
    login(client, "v")
    assert client.post("/api/v1/wazuh/sync").status_code == 403
