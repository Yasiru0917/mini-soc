"""Phase 4: alert triage, incident workflow, notes, evidence."""

import hashlib

from app.models import Alert
from app.models.enums import AlertSource, Role, Severity
from tests.conftest import login

A = "/api/v1/alerts"
I = "/api/v1/incidents"  # noqa: E741


def make_alert(analyst_client, **overrides):
    body = {"title": "Suspicious login", "severity": "high", "src_ip": "192.168.56.20"} | overrides
    resp = analyst_client.post(A, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------- alerts
def test_manual_alert_is_forced_to_source_manual(analyst_client):
    alert = make_alert(analyst_client, source="wazuh", is_simulated=True)  # extra fields ignored
    assert alert["source"] == "manual"
    assert alert["is_simulated"] is False
    assert alert["status"] == "new"


def test_alert_ip_validation(analyst_client):
    resp = analyst_client.post(A, json={"title": "Bad", "severity": "low", "src_ip": "999.1.1.1"})
    assert resp.status_code == 422


def test_viewer_cannot_create_alerts(client, make_user):
    make_user("v1", Role.VIEWER)
    login(client, "v1")
    assert client.post(A, json={"title": "x" * 5, "severity": "low"}).status_code == 403
    assert client.get(A).status_code == 200  # but can read


def test_alert_filters_and_search(analyst_client, db):
    make_alert(analyst_client, title="SSH brute force", severity="high")
    make_alert(analyst_client, title="Port scan", severity="low", src_ip="192.168.56.99")
    db.add(Alert(title="[DEMO] x", severity=Severity.CRITICAL, source=AlertSource.DEMO, is_simulated=True))
    db.commit()

    assert analyst_client.get(A).json()["total"] == 3
    assert analyst_client.get(A, params={"include_simulated": False}).json()["total"] == 2
    assert analyst_client.get(A, params={"severity": "low"}).json()["items"][0]["title"] == "Port scan"
    assert analyst_client.get(A, params={"q": "56.99"}).json()["total"] == 1
    # LIKE wildcards in the search are treated as literal text
    assert analyst_client.get(A, params={"q": "%"}).json()["total"] == 0


def test_alert_status_workflow(analyst_client):
    alert = make_alert(analyst_client)
    url = f"{A}/{alert['id']}"
    # new -> closed is not allowed (must be resolved/false positive first)
    resp = analyst_client.patch(url, json={"status": "closed"})
    assert resp.status_code == 409 and "Allowed" in resp.json()["detail"]
    assert analyst_client.patch(url, json={"status": "investigating"}).status_code == 200
    assert analyst_client.patch(url, json={"status": "resolved"}).status_code == 200
    assert analyst_client.patch(url, json={"status": "closed"}).json()["status"] == "closed"


# ---------------------------------------------------------------- incidents
def test_create_incident_from_alerts(analyst_client):
    a1 = make_alert(analyst_client, severity="medium")
    a2 = make_alert(analyst_client, severity="critical")
    resp = analyst_client.post(I, json={"title": "Account compromise", "alert_ids": [a1["id"], a2["id"]]})
    assert resp.status_code == 201, resp.text
    inc = resp.json()
    assert inc["severity"] == "critical"  # worst of the linked alerts
    assert inc["alert_count"] == 2
    assert {a["status"] for a in inc["alerts"]} == {"investigating"}  # linked alerts move on
    assert inc["created_by"] == "analyst1"


def test_alert_cannot_be_in_two_incidents(analyst_client):
    a = make_alert(analyst_client)
    analyst_client.post(I, json={"title": "First", "alert_ids": [a["id"]]})
    resp = analyst_client.post(I, json={"title": "Second", "alert_ids": [a["id"]]})
    assert resp.status_code == 409


def test_incident_from_demo_alert_is_marked_simulated(analyst_client, db):
    demo = Alert(title="[DEMO] y", severity=Severity.HIGH, source=AlertSource.DEMO, is_simulated=True)
    db.add(demo)
    db.commit()
    inc = analyst_client.post(I, json={"title": "From demo", "alert_ids": [demo.id]}).json()
    assert inc["is_simulated"] is True


def test_resolution_required_before_resolving(analyst_client):
    inc = analyst_client.post(I, json={"title": "Malware on host", "severity": "high"}).json()
    url = f"{I}/{inc['id']}"
    analyst_client.patch(url, json={"status": "investigating"})
    blocked = analyst_client.patch(url, json={"status": "resolved"})
    assert blocked.status_code == 422 and "resolution" in blocked.json()["detail"]

    ok = analyst_client.patch(url, json={"resolution": "Host reimaged", "recommendations": "Patch weekly",
                                         "status": "resolved"})
    assert ok.status_code == 200 and ok.json()["status"] == "resolved"
    closed = analyst_client.patch(url, json={"status": "closed"}).json()
    assert closed["closed_at"] is not None


def test_assignee_must_be_analyst_or_admin(analyst_client, make_user):
    viewer = make_user("v2", Role.VIEWER)
    inc = analyst_client.post(I, json={"title": "Assign test", "severity": "low"}).json()
    assert analyst_client.patch(f"{I}/{inc['id']}", json={"assignee_id": viewer.id}).status_code == 400
    users = analyst_client.get("/api/v1/users/assignable").json()
    assert [u["username"] for u in users] == ["analyst1"]


def test_notes_are_recorded_with_author(analyst_client):
    inc = analyst_client.post(I, json={"title": "Notes test", "severity": "low"}).json()
    resp = analyst_client.post(f"{I}/{inc['id']}/notes", json={"body": "Checked firewall logs."})
    assert resp.status_code == 201 and resp.json()["author"] == "analyst1"
    detail = analyst_client.get(f"{I}/{inc['id']}").json()
    assert detail["notes"][0]["body"] == "Checked firewall logs."


# ---------------------------------------------------------------- evidence
def test_evidence_upload_hash_and_download(analyst_client):
    inc = analyst_client.post(I, json={"title": "Evidence test", "severity": "low"}).json()
    content = b"Nov 24 10:00:01 host sshd[1]: Failed password for root from 192.168.56.20\n"
    resp = analyst_client.post(f"{I}/{inc['id']}/evidence",
                               files={"file": ("../../etc/auth.log", content, "text/plain")},
                               data={"description": "auth log excerpt"})
    assert resp.status_code == 201, resp.text
    ev = resp.json()
    assert ev["sha256"] == hashlib.sha256(content).hexdigest()
    assert ev["original_name"] == "auth.log"  # path components stripped

    dl = analyst_client.get(f"/api/v1/evidence/{ev['id']}/download")
    assert dl.status_code == 200 and dl.content == content
    assert dl.headers["content-type"] == "application/octet-stream"
    assert "attachment" in dl.headers["content-disposition"]


def test_evidence_rejects_disguised_file(analyst_client):
    inc = analyst_client.post(I, json={"title": "Disguise test", "severity": "low"}).json()
    fake_png = b"MZ\x90\x00 this is really a windows executable"
    resp = analyst_client.post(f"{I}/{inc['id']}/evidence", files={"file": ("photo.png", fake_png, "image/png")})
    assert resp.status_code == 400 and "does not match" in resp.json()["detail"]


def test_evidence_rejects_disallowed_extension(analyst_client):
    inc = analyst_client.post(I, json={"title": "Ext test", "severity": "low"}).json()
    resp = analyst_client.post(f"{I}/{inc['id']}/evidence", files={"file": ("run.exe", b"MZ..", "x")})
    assert resp.status_code == 415


def test_evidence_description_only(analyst_client):
    inc = analyst_client.post(I, json={"title": "Desc test", "severity": "low"}).json()
    resp = analyst_client.post(f"{I}/{inc['id']}/evidence", data={"description": "Attacker IP 203.0.113.9"})
    assert resp.status_code == 201 and resp.json()["has_file"] is False


def test_oversized_upload_rejected_before_reading(analyst_client):
    resp = analyst_client.post(f"{I}/1/evidence", content=b"x",
                               headers={"Content-Type": "multipart/form-data; boundary=x",
                                        "Content-Length": str(500 * 1024 * 1024)})
    assert resp.status_code == 413
