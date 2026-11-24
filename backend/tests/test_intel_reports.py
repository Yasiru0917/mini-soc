"""Phase 8: threat-intelligence lookups (simulated providers) and reports."""

import csv
import io

import httpx
import pytest

from app.core.config import get_settings
from app.integrations.threatintel import providers
from app.models import Alert
from app.models.enums import AlertSource, Severity
from app.reports.csv_export import safe_cell
from app.reports.pdf import esc

LOOKUP = "/api/v1/threat-intel/lookup"


# ---------------------------------------------------------------- indicator validation
@pytest.mark.parametrize(("raw", "kind"), [("8.8.8.8", "ip"), ("Example.COM", "domain"),
                                          ("44d88612fea8a8f36de82e1278abb02f", "hash"),
                                          ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "hash")])
def test_indicator_classification(raw, kind):
    assert providers.classify(raw)[0] == kind


@pytest.mark.parametrize("private", ["192.168.56.101", "10.0.0.5", "127.0.0.1", "fe80::1", "192.0.2.10",
                                     "fileserver.local", "dc01.corp"])
def test_private_and_internal_indicators_are_never_sent(private):
    with pytest.raises(providers.IndicatorError):
        providers.classify(private)


def test_garbage_indicator_rejected():
    with pytest.raises(providers.IndicatorError):
        providers.classify("not an indicator; DROP TABLE")


# ---------------------------------------------------------------- lookups (simulated)
@pytest.fixture
def keys(monkeypatch):
    s = get_settings().model_copy(update={"abuseipdb_api_key": "k1", "virustotal_api_key": "k2", "otx_api_key": "k3"})
    monkeypatch.setattr("app.api.v1.threatintel.get_settings", lambda: s)
    calls = []

    def handler(req: httpx.Request):
        calls.append(req.url.host)
        if req.url.host == "api.abuseipdb.com":
            assert req.headers["key"] == "k1"
            return httpx.Response(200, json={"data": {"abuseConfidenceScore": 92, "totalReports": 41,
                                                      "countryCode": "NL", "isp": "Example ISP"}})
        if req.url.host == "www.virustotal.com":
            return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {
                "malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 10}}}})
        if req.url.host == "otx.alienvault.com":
            return httpx.Response(429)
        return httpx.Response(404)

    monkeypatch.setattr(providers, "transport_override", httpx.MockTransport(handler))
    return calls


def test_lookup_without_keys_is_honest(analyst_client):
    body = analyst_client.post(LOOKUP, json={"indicator": "8.8.8.8"}).json()
    assert body["providers_answered"] == 0 and body["overall_verdict"] is None
    assert {r["status"] for r in body["results"]} == {"not_configured"}


def test_lookup_reports_each_provider_with_source_and_reliability(analyst_client, keys):
    body = analyst_client.post(LOOKUP, json={"indicator": "8.8.4.4"}).json()
    by = {r["provider"]: r for r in body["results"]}
    assert by["AbuseIPDB"]["verdict"] == "malicious" and by["AbuseIPDB"]["score_label"] == "Abuse confidence 92/100"
    assert by["VirusTotal"]["verdict"] == "suspicious" and "1/71" in by["VirusTotal"]["score_label"]
    assert by["AlienVault OTX"]["status"] == "error" and "rate limit" in by["AlienVault OTX"]["error"]
    assert all(r["reliability_note"] and r["queried_at"] for r in body["results"])
    assert by["AbuseIPDB"]["reference_url"] == "https://www.abuseipdb.com/check/8.8.4.4"
    assert body["overall_verdict"] == "malicious"


def test_results_are_cached(analyst_client, keys):
    analyst_client.post(LOOKUP, json={"indicator": "8.8.4.4"})
    first_calls = len(keys)
    second = analyst_client.post(LOOKUP, json={"indicator": "8.8.4.4"}).json()
    # AbuseIPDB and VirusTotal answers are reused; only the failed OTX call is retried.
    assert len(keys) == first_calls + 1
    assert {r["provider"]: r["cached"] for r in second["results"]} == {
        "AbuseIPDB": True, "VirusTotal": True, "AlienVault OTX": False}


def test_private_ip_lookup_refused_by_api(analyst_client, keys):
    resp = analyst_client.post(LOOKUP, json={"indicator": "192.168.56.101"})
    assert resp.status_code == 400 and keys == []  # nothing left the machine


# ---------------------------------------------------------------- reports
def test_csv_injection_is_neutralised():
    assert safe_cell('=HYPERLINK("http://evil.example","x")').startswith("'=")
    assert safe_cell("+1+1") == "'+1+1" and safe_cell("@SUM(A1)") == "'@SUM(A1)"
    assert safe_cell("normal title") == "normal title"


def test_pdf_markup_is_escaped():
    assert esc('<font size="99">x</font> & <a href="http://evil">') == (
        '&lt;font size="99"&gt;x&lt;/font&gt; &amp; &lt;a href="http://evil"&gt;')


def test_incident_pdf_and_csv_downloads(analyst_client, db):
    db.add(Alert(title='=cmd|"/c calc"!A1 <b>bold</b>', severity=Severity.HIGH, source=AlertSource.LOG_RULE,
                 detection_rule_id="R-001", src_ip="203.0.113.50"))
    db.commit()
    inc = analyst_client.post("/api/v1/incidents", json={"title": "Report <test> & co", "alert_ids": [1]}).json()
    analyst_client.post(f"/api/v1/incidents/{inc['id']}/notes", json={"body": "Investigated."})

    pdf = analyst_client.get(f"/api/v1/reports/incidents/{inc['id']}.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")
    assert "attachment" in pdf.headers["content-disposition"] and len(pdf.headers["x-report-sha256"]) == 64

    resp = analyst_client.get(f"/api/v1/reports/incidents/{inc['id']}.csv")
    rows = list(csv.reader(io.StringIO(resp.content.decode("utf-8-sig"))))
    alert_row = next(r for r in rows if r[0] == "alert")
    assert alert_row[2].startswith("'=")  # formula neutralised

    history = analyst_client.get("/api/v1/reports").json()
    assert {h["kind"] for h in history} == {"incident_pdf", "incident_csv"}


def test_alerts_csv_export_filters(analyst_client, db):
    db.add_all([Alert(title="a", severity=Severity.LOW, source=AlertSource.MANUAL),
                Alert(title="b", severity=Severity.HIGH, source=AlertSource.DEMO, is_simulated=True)])
    db.commit()
    resp = analyst_client.get("/api/v1/reports/alerts.csv", params={"include_simulated": False})
    rows = list(csv.reader(io.StringIO(resp.content.decode("utf-8-sig"))))
    assert len(rows) == 2 and rows[1][4] == "a"
