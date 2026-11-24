"""Phase 5: scan scope enforcement, Nmap runner/parser, findings, inventory."""

import os
import shutil
from pathlib import Path

import pytest
from sqlalchemy import select

from app.integrations.nmap import runner
from app.integrations.nmap.scope import ScopeError, ensure_in_scope, parse_target, validate_scope
from app.models import Alert, AuditLog, Device, Scan

SAMPLE_XML = (Path(__file__).parent / "fixtures" / "nmap_sample.xml").read_text()
LAB = [parse_target("192.168.56.0/24")]


# ---------------------------------------------------------------- scope (pure functions)
@pytest.mark.parametrize("target", ["192.168.56.1", "192.168.56.0/24", "192.168.56.128/25"])
def test_targets_inside_lab_scope_are_allowed(target):
    ensure_in_scope(parse_target(target), LAB)


@pytest.mark.parametrize("target", ["192.168.1.10", "8.8.8.8", "10.0.0.0/24", "192.168.0.0/16"])
def test_targets_outside_scope_or_too_large_are_refused(target):
    with pytest.raises(ScopeError):
        ensure_in_scope(parse_target(target), LAB)


@pytest.mark.parametrize("bad", ["scanme.nmap.org", "192.168.56.1; calc.exe", "-oN /tmp/x", "192.168.56.1 -p-",
                                 "$(whoami)", ""])
def test_hostnames_and_injection_attempts_are_not_valid_targets(bad):
    with pytest.raises(ScopeError):
        parse_target(bad)


@pytest.mark.parametrize("public", ["8.8.8.0/24", "100.64.0.0/24"])  # internet, carrier-grade NAT
def test_non_private_scope_requires_explicit_confirmation(public):
    with pytest.raises(ScopeError, match="not a private"):
        validate_scope([public], allow_public=False)
    assert validate_scope([public], allow_public=True)


def test_private_scope_accepted():
    assert validate_scope(["192.168.56.0/24", "10.10.0.0/16"], allow_public=False)


def test_scope_entries_limited_in_size():
    with pytest.raises(ScopeError, match="too large"):
        validate_scope(["10.0.0.0/8"], allow_public=False)


# ---------------------------------------------------------------- parser & command
def test_parse_nmap_xml():
    hosts = runner.parse_xml(SAMPLE_XML)
    assert [h.ip for h in hosts] == ["192.168.56.101", "192.168.56.102"]
    up = hosts[0]
    assert up.state == "up" and up.hostname == "metasploitable.lab" and up.vendor.startswith("Oracle")
    assert [(p.port, p.state) for p in up.ports] == [(22, "open"), (23, "open"), (80, "open"), (3306, "closed")]
    assert up.ports[0].product == "OpenSSH"


def test_xml_entity_attack_is_blocked():
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
    with pytest.raises(runner.NmapError, match="entity"):  # defusedxml refuses entity declarations
        runner.parse_xml(evil)


def test_command_is_argument_list_without_shell(monkeypatch):
    monkeypatch.setattr(runner, "resolve_binary", lambda _p: "/usr/bin/nmap")
    cmd = runner.build_command("nmap", "quick", "192.168.56.0/24")
    assert cmd == ["/usr/bin/nmap", "-sT", "--top-ports", "100", "-T4", "--host-timeout", "5m", "-oX", "-",
                   "192.168.56.0/24"]


# ---------------------------------------------------------------- API
@pytest.fixture
def fake_nmap(monkeypatch):
    monkeypatch.setattr(runner, "resolve_binary", lambda _p: "nmap")
    monkeypatch.setattr(runner, "run_nmap", lambda cmd, timeout: SAMPLE_XML)


def test_scan_out_of_scope_is_denied_and_audited(analyst_client, db):
    resp = analyst_client.post("/api/v1/scans", json={"target": "8.8.8.8", "profile": "quick"})
    assert resp.status_code == 403 and "outside the authorized scope" in resp.json()["detail"]
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "scan.request"))
    assert entry.outcome == "denied" and entry.target == "8.8.8.8"
    assert db.scalar(select(Scan)) is None  # nothing was queued


def test_unknown_profile_rejected(analyst_client):
    resp = analyst_client.post("/api/v1/scans", json={"target": "192.168.56.1", "profile": "-A -p-"})
    assert resp.status_code == 422


def test_viewer_cannot_scan(client, make_user):
    from app.models.enums import Role
    from tests.conftest import login
    make_user("v", Role.VIEWER)
    login(client, "v")
    assert client.post("/api/v1/scans", json={"target": "192.168.56.1", "profile": "quick"}).status_code == 403


def test_scan_stores_inventory_and_raises_findings(analyst_client, db, fake_nmap):
    resp = analyst_client.post("/api/v1/scans", json={"target": "192.168.56.0/24", "profile": "quick"})
    assert resp.status_code == 202
    scan = analyst_client.get(f"/api/v1/scans/{resp.json()['id']}").json()
    assert scan["status"] == "completed", scan["error"]
    assert scan["hosts_up"] == 1 and scan["open_ports"] == 3

    devices = analyst_client.get("/api/v1/devices").json()
    assert len(devices) == 1 and devices[0]["ip"] == "192.168.56.101"
    assert [p["port"] for p in devices[0]["ports"]] == [22, 23, 80]  # only open ports listed

    alerts = db.scalars(select(Alert)).all()
    # Telnet is a risky port. First scan = baseline, so no "new device" alert.
    assert [a.title for a in alerts] == ["Telnet exposed on 192.168.56.101:23"]
    assert alerts[0].source == "nmap" and alerts[0].raw_reference == f"scan:{scan['id']}"
    assert alerts[0].is_simulated is False


def test_repeat_scan_does_not_duplicate_open_alerts(analyst_client, db, fake_nmap):
    for _ in range(2):
        analyst_client.post("/api/v1/scans", json={"target": "192.168.56.101", "profile": "quick"})
    assert len(db.scalars(select(Alert)).all()) == 1
    assert len(db.scalars(select(Device)).all()) == 1


def test_admin_can_change_scope_and_it_is_enforced(admin_client):
    bad = admin_client.put("/api/v1/settings/scan-scope", json={"cidrs": ["8.8.8.0/24"]})
    assert bad.status_code == 400
    ok = admin_client.put("/api/v1/settings/scan-scope", json={"cidrs": ["10.20.30.0/24"]})
    assert ok.status_code == 200 and ok.json()["cidrs"] == ["10.20.30.0/24"]
    resp = admin_client.post("/api/v1/scans", json={"target": "192.168.56.1", "profile": "discovery"})
    assert resp.status_code == 403  # old lab range no longer in scope


def test_analyst_cannot_change_scope(analyst_client):
    resp = analyst_client.put("/api/v1/settings/scan-scope", json={"cidrs": ["192.168.0.0/16"]})
    assert resp.status_code == 403


# ---------------------------------------------------------------- optional live test
@pytest.mark.skipif(os.environ.get("RUN_NMAP_TESTS") != "1" or shutil.which("nmap") is None,
                    reason="set RUN_NMAP_TESTS=1 to run a real scan of 192.168.56.1 (this PC)")
def test_live_scan_of_own_host(analyst_client):
    resp = analyst_client.post("/api/v1/scans", json={"target": "192.168.56.1", "profile": "quick"})
    scan = analyst_client.get(f"/api/v1/scans/{resp.json()['id']}").json()
    assert scan["status"] == "completed", scan["error"]
    assert scan["hosts_up"] == 1
