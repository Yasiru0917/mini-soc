"""Threat-intelligence providers.

IMPORTANT - how to read reputation data:
  A reputation score is a third party's OPINION, based on what they have
  seen. It is evidence to weigh, not proof. A "clean" result does not mean
  an IP is safe (it may simply be new), and a "malicious" result may be
  outdated (IPs get reassigned). That's why every result carries:
    provider  - who said it
    queried_at- when we asked
    score     - the provider's own measure, with its meaning spelled out
    reliability_note - how that kind of source should be weighted

PRIVACY: private/internal indicators are never sent to outside services,
since doing so would leak details of your network.
"""

import ipaddress
import re
from datetime import UTC, datetime

import httpx

from app.core.config import Settings

TIMEOUT = httpx.Timeout(10.0, connect=5.0)
# Tests set this to an httpx.MockTransport so no real requests are made.
transport_override: httpx.BaseTransport | None = None

_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
_HASH = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")
_INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".home", ".corp", ".localdomain", ".lab", ".arpa")


class IndicatorError(ValueError):
    pass


def classify(indicator: str) -> tuple[str, str]:
    """Return (type, normalised value). Types: ip | domain | hash."""
    value = indicator.strip().lower()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:
            raise IndicatorError(f"{ip} is a private, internal or reserved address. It has no public reputation "
                                 "and is never sent to external services.")
        return "ip", str(ip)
    if _HASH.match(value):
        return "hash", value
    if _DOMAIN.match(value):
        if value.endswith(_INTERNAL_SUFFIXES):
            raise IndicatorError("Internal domain names are not sent to external services.")
        return "domain", value
    raise IndicatorError("Enter a public IP address, a domain name, or an MD5/SHA-1/SHA-256 file hash.")


def make_result(provider: str, status: str, **kw) -> dict:
    return {"provider": provider, "status": status, "verdict": kw.get("verdict", "unknown"),
            "score": kw.get("score"), "score_label": kw.get("score_label"), "summary": kw.get("summary", {}),
            "reference_url": kw.get("reference_url"), "reliability_note": kw.get("note", ""),
            "error": kw.get("error"), "queried_at": datetime.now(UTC).isoformat(), "cached": False}


def _get(url: str, headers: dict, params: dict | None = None) -> httpx.Response:
    with httpx.Client(timeout=TIMEOUT, transport=transport_override) as client:
        return client.get(url, headers=headers, params=params)


def _http_error(resp: httpx.Response) -> str:
    if resp.status_code in (401, 403):
        return "API key rejected by provider."
    if resp.status_code == 429:
        return "Provider rate limit reached; try again later."
    return f"Provider returned HTTP {resp.status_code}."


# ---------------------------------------------------------------- AbuseIPDB
ABUSE_NOTE = ("Crowd-sourced abuse reports. The confidence score reflects how many and how recent reports are; "
              "shared IPs (VPNs, cloud, CGNAT) can collect reports caused by other users.")


def abuseipdb(kind: str, value: str, s: Settings) -> dict:
    name = "AbuseIPDB"
    if not s.abuseipdb_api_key:
        return make_result(name, "not_configured", note=ABUSE_NOTE)
    if kind != "ip":
        return make_result(name, "unsupported", note="AbuseIPDB only checks IP addresses.")
    resp = _get("https://api.abuseipdb.com/api/v2/check",
                {"Key": s.abuseipdb_api_key, "Accept": "application/json"},
                {"ipAddress": value, "maxAgeInDays": 90})
    if resp.status_code != 200:
        return make_result(name, "error", error=_http_error(resp), note=ABUSE_NOTE)
    d = resp.json().get("data", {})
    score, reports = d.get("abuseConfidenceScore", 0), d.get("totalReports", 0)
    verdict = ("malicious" if score >= 75 else "suspicious" if score >= 25
               else "unknown" if reports == 0 else "harmless")
    return make_result(name, "ok", verdict=verdict, score=score, score_label=f"Abuse confidence {score}/100",
                   summary={"Reports (90 days)": reports, "Country": d.get("countryCode"), "ISP": d.get("isp"),
                            "Usage type": d.get("usageType"), "Last reported": d.get("lastReportedAt"),
                            "Allow-listed": d.get("isWhitelisted")},
                   reference_url=f"https://www.abuseipdb.com/check/{value}", note=ABUSE_NOTE)


# ---------------------------------------------------------------- VirusTotal
VT_NOTE = ("Aggregates verdicts from ~70 security vendors. A few detections can be false positives; "
           "a clean result for a new indicator only means no vendor has flagged it yet.")
VT_PATHS = {"ip": ("ip_addresses", "ip-address"), "domain": ("domains", "domain"), "hash": ("files", "file")}


def virustotal(kind: str, value: str, s: Settings) -> dict:
    name = "VirusTotal"
    if not s.virustotal_api_key:
        return make_result(name, "not_configured", note=VT_NOTE)
    api_path, gui_path = VT_PATHS[kind]
    resp = _get(f"https://www.virustotal.com/api/v3/{api_path}/{value}", {"x-apikey": s.virustotal_api_key})
    ref = f"https://www.virustotal.com/gui/{gui_path}/{value}"
    if resp.status_code == 404:
        return make_result(name, "ok", verdict="unknown", score_label="Not in VirusTotal's dataset",
                       reference_url=ref, note=VT_NOTE)
    if resp.status_code != 200:
        return make_result(name, "error", error=_http_error(resp), note=VT_NOTE)
    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    total = sum(v for v in stats.values() if isinstance(v, int))
    verdict = ("malicious" if mal >= 3 else "suspicious" if (mal or sus)
               else "harmless" if stats.get("harmless", 0) else "unknown")
    return make_result(name, "ok", verdict=verdict, score=mal, score_label=f"{mal}/{total} vendors flag as malicious",
                   summary={"Malicious": mal, "Suspicious": sus, "Harmless": stats.get("harmless"),
                            "Undetected": stats.get("undetected"), "Community reputation": attrs.get("reputation"),
                            "Owner / AS": attrs.get("as_owner"), "File type": attrs.get("type_description")},
                   reference_url=ref, note=VT_NOTE)


# ---------------------------------------------------------------- AlienVault OTX
OTX_NOTE = ("Community 'pulses' (threat reports) that mention the indicator. Quality varies by author; "
            "a pulse means 'seen in a report', not 'confirmed malicious'.")


def otx(kind: str, value: str, s: Settings) -> dict:
    name = "AlienVault OTX"
    if not s.otx_api_key:
        return make_result(name, "not_configured", note=OTX_NOTE)
    section = {"ip": "IPv6" if ":" in value else "IPv4", "domain": "domain", "hash": "file"}[kind]
    resp = _get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
                {"X-OTX-API-KEY": s.otx_api_key})
    if resp.status_code != 200:
        return make_result(name, "error", error=_http_error(resp), note=OTX_NOTE)
    data = resp.json()
    pulses = data.get("pulse_info", {}).get("count", 0)
    names = [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:5]]
    ref_section = {"ip": "ip", "domain": "domain", "hash": "file"}[kind]
    return make_result(name, "ok", verdict="suspicious" if pulses else "unknown", score=pulses,
                   score_label=f"Mentioned in {pulses} community pulse(s)",
                   summary={"Pulses": pulses, "Recent pulse titles": "; ".join(n for n in names if n) or None,
                            "Country": data.get("country_name")},
                   reference_url=f"https://otx.alienvault.com/indicator/{ref_section}/{value}", note=OTX_NOTE)


PROVIDERS = (("AbuseIPDB", abuseipdb), ("VirusTotal", virustotal), ("AlienVault OTX", otx))
