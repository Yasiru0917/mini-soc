"""Phase 6: log parsers, detection rules, uploads, packet capture analysis."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app.detection import parsers
from app.detection.events import AUTH_FAILURE, HTTP_REQUEST, LogEvent
from app.detection.rules import run_log_rules, web_enumeration
from app.integrations.base import resolve_binary
from app.integrations.tshark import analyzer
from app.models import Alert
from scripts.make_sample_pcap import write_pcap

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
NOW = datetime(2026, 11, 25, tzinfo=UTC)


def rules_hit(detections):
    return sorted({d.rule_id for d in detections})


# ---------------------------------------------------------------- parsers
def test_auth_log_parsing():
    ev = parsers.parse_auth_line(1, "Nov 24 10:02:14 labsrv sshd[1313]: Failed password for root from "
                                    "203.0.113.50 port 41030 ssh2", NOW)
    assert ev.event_type == AUTH_FAILURE and ev.src_ip == "203.0.113.50" and ev.user == "root"
    assert ev.timestamp == datetime(2026, 11, 24, 10, 2, 14, tzinfo=UTC)


def test_syslog_without_year_never_lands_in_the_future():
    ev = parsers.parse_auth_line(1, "Dec 31 23:00:00 h sshd[1]: Failed password for x from 192.0.2.1 port 1 ssh2",
                                 datetime(2026, 1, 2, tzinfo=UTC))
    assert ev.timestamp.year == 2025


def test_access_log_parsing():
    ev = parsers.parse_access_line(3, '198.51.100.23 - - [24/Nov/2026:10:03:10 +0000] "GET /a?b=1 HTTP/1.1" 404 '
                                      '196 "-" "curl"', NOW)
    assert (ev.event_type, ev.src_ip, ev.method, ev.path, ev.status) == (HTTP_REQUEST, "198.51.100.23", "GET",
                                                                        "/a?b=1", 404)


@pytest.mark.parametrize(("name", "fmt"), [("sample-auth.log", "auth"), ("sample-access.log", "access"),
                                           ("sample-events.jsonl", "jsonl")])
def test_format_auto_detection(name, fmt):
    assert parsers.detect_format((SAMPLES / name).read_text().splitlines()) == fmt


def test_unrecognised_lines_are_skipped_not_guessed():
    events, skipped = parsers.parse_lines("access", ["not a log line", "", "still not"])
    assert events == [] and skipped == 2


# ---------------------------------------------------------------- rules
def _rules_for(sample: str, fmt: str):
    events, _ = parsers.parse_lines(fmt, (SAMPLES / sample).read_text().splitlines())
    return run_log_rules(events)


def test_auth_sample_triggers_brute_force_and_compromise():
    detections = _rules_for("sample-auth.log", "auth")
    assert rules_hit(detections) == ["R-001", "R-002"]
    r2 = next(d for d in detections if d.rule_id == "R-002")
    assert r2.src_ip == "203.0.113.50" and "msfadmin" in r2.title
    # The analyst's single typo from the lab host must NOT count as an attack.
    assert all(d.src_ip != "192.168.56.1" for d in detections)


def test_access_sample_triggers_web_rules():
    detections = _rules_for("sample-access.log", "access")
    assert rules_hit(detections) == ["R-003", "R-004", "R-005"]
    assert {d.src_ip for d in detections if d.rule_id in ("R-003", "R-004")} == {"198.51.100.23"}


def test_brute_force_threshold_is_exact():
    base = datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
    four = [LogEvent(i, AUTH_FAILURE, base + timedelta(seconds=10 * i), src_ip="192.0.2.9") for i in range(4)]
    assert run_log_rules(four) == []  # 4 failures: below threshold
    five = four + [LogEvent(5, AUTH_FAILURE, base + timedelta(seconds=50), src_ip="192.0.2.9")]
    assert rules_hit(run_log_rules(five)) == ["R-001"]
    spread = [LogEvent(i, AUTH_FAILURE, base + timedelta(minutes=i), src_ip="192.0.2.9") for i in range(5)]
    assert run_log_rules(spread) == []  # 5 failures but spread over 4 minutes (window is 2)


def test_404_burst_needs_twenty_within_a_minute():
    base = datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
    hits = [LogEvent(i, HTTP_REQUEST, base + timedelta(seconds=i * 2), src_ip="192.0.2.7", status=404, path="/x")
            for i in range(19)]
    assert web_enumeration(hits) == []
    hits.append(LogEvent(20, HTTP_REQUEST, base + timedelta(seconds=40), src_ip="192.0.2.7", status=404, path="/y"))
    assert len(web_enumeration(hits)) == 1


def test_double_encoded_traversal_is_caught():
    ev = LogEvent(1, HTTP_REQUEST, NOW, src_ip="192.0.2.1", path="/f?p=%252e%252e%252fetc%252fpasswd", status=200)
    assert rules_hit(run_log_rules([ev])) == ["R-003"]


# ---------------------------------------------------------------- upload API
def upload(client, name, content=None, log_type="auto"):
    data = content if content is not None else (SAMPLES / name).read_bytes()
    return client.post("/api/v1/logs/upload", files={"file": (name, data, "application/octet-stream")},
                       data={"log_type": log_type})


def test_upload_auth_log_creates_traceable_alerts(analyst_client, db):
    resp = upload(analyst_client, "sample-auth.log")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["log_type"] == "auth" and body["alerts_raised"] == 2 and body["events_parsed"] == 16
    alerts = db.scalars(select(Alert).order_by(Alert.id)).all()
    assert {a.detection_rule_id for a in alerts} == {"R-001", "R-002"}
    for a in alerts:
        assert a.source == "log_rule" and not a.is_simulated
        assert a.raw_reference.startswith(f"upload:{body['id']}:lines:")
        assert "sample-auth.log" in a.description and "MITRE" in a.description
    # The alert time is when the attack happened, not when the file was uploaded.
    assert alerts[0].detected_at.date().isoformat().endswith("11-24")

    events = analyst_client.get(f"/api/v1/logs/{body['id']}/events", params={"event_type": "auth_failure"}).json()
    assert events["total"] == 8  # 7 from the attacker + 1 typo by the analyst


def test_same_file_twice_is_refused(analyst_client):
    assert upload(analyst_client, "sample-access.log").status_code == 201
    second = upload(analyst_client, "sample-access.log")
    assert second.status_code == 409 and "already analysed" in second.json()["detail"]


def test_unknown_format_is_reported_not_guessed(analyst_client, db):
    resp = upload(analyst_client, "notes.txt", b"hello\nthis is not a log\n")
    assert resp.status_code == 422 and "recognise" in resp.json()["detail"]
    assert db.scalar(select(Alert)) is None


def test_binary_disguised_as_log_is_rejected(analyst_client):
    resp = upload(analyst_client, "auth.log", b"\x7fELF\x02\x01\x01\x00\x00\x00binary")
    assert resp.status_code == 400


def test_rules_catalogue(analyst_client):
    rules = analyst_client.get("/api/v1/logs/rules").json()
    assert [r["id"] for r in rules] == ["R-001", "R-002", "R-003", "R-004", "R-005", "R-006"]
    assert all(r["mitre"] for r in rules)


# ---------------------------------------------------------------- pcap
def test_pcap_summary_and_port_scan_detection_from_fields():
    rows = [f"1795629600.{i:06d}\t203.0.113.50\t192.168.56.101\tTCP\t{p}\t\t1\t0\t\t\t54\t\t"
            for i, p in enumerate(range(1, 26))]
    rows.append("1795629601.5\t192.168.56.101\t192.168.56.1\tDNS\t\t53\t\t\texample.com\t0\t71\t\t")
    summary, detections = analyzer.summarise("\n".join(rows))
    assert summary["packets"] == 26
    assert summary["dns_queries"] == [("example.com", 1)]
    assert len(detections) == 1 and detections[0].rule_id == "R-006" and detections[0].count == 25


@pytest.mark.skipif(resolve_binary("tshark") is None, reason="TShark not installed")
def test_pcap_upload_end_to_end_with_real_tshark(analyst_client, db, tmp_path):
    pcap = write_pcap(tmp_path / "scan.pcap")
    resp = upload(analyst_client, "scan.pcap", pcap.read_bytes())
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["log_type"] == "pcap" and body["events_parsed"] == 81
    assert body["summary"]["dns_queries"][0][0] == "example.com"
    alert = db.scalar(select(Alert))
    assert alert.detection_rule_id == "R-006" and alert.source == "pcap"
    assert alert.src_ip == "203.0.113.50" and alert.dst_ip == "192.168.56.101"
