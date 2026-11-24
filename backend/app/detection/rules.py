"""Detection rules.

Each rule is small, readable and documented, with:
  * a stable ID (R-00x) that every alert records,
  * the exact logic and thresholds,
  * the MITRE ATT&CK technique it maps to (the industry's shared vocabulary
    for attacker behaviour - https://attack.mitre.org).

Thresholds are deliberately simple and are listed in docs/DETECTION_RULES.md.
"""

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import unquote_plus

from app.detection.events import AUTH_FAILURE, AUTH_SUCCESS, HTTP_REQUEST, Detection, LogEvent
from app.models.enums import Severity

MAX_SAMPLES = 5


@dataclass(frozen=True)
class RuleInfo:
    id: str
    name: str
    logic: str
    mitre: str
    severity: Severity
    applies_to: str  # "logs" | "pcap"


RULES: dict[str, RuleInfo] = {r.id: r for r in (
    RuleInfo("R-001", "SSH brute force", "≥ 5 failed logins from one IP within 2 minutes",
             "T1110 Brute Force", Severity.HIGH, "logs"),
    RuleInfo("R-002", "Successful login after brute force",
             "A successful login from an IP that triggered ≥ 5 failures in the previous 10 minutes",
             "T1110 / T1078 Valid Accounts", Severity.CRITICAL, "logs"),
    RuleInfo("R-003", "Web path traversal", "Request path contains ../ or ..\\ (also URL-encoded)",
             "T1190 Exploit Public-Facing Application", Severity.HIGH, "logs"),
    RuleInfo("R-004", "SQL injection pattern",
             "Decoded URL matches SQLi tokens: UNION SELECT, ' OR '1'='1, OR 1=1, SLEEP(, information_schema…",
             "T1190 Exploit Public-Facing Application", Severity.HIGH, "logs"),
    RuleInfo("R-005", "Web scanning / enumeration", "≥ 20 HTTP 404 responses to one IP within 1 minute",
             "T1595.003 Wordlist Scanning", Severity.MEDIUM, "logs"),
    RuleInfo("R-006", "Port scan in packet capture",
             "One source sends TCP SYN (no ACK) to ≥ 20 distinct ports on one destination",
             "T1046 Network Service Discovery", Severity.MEDIUM, "pcap"),
)}


def _detection(rule_id: str, title: str, events: list[LogEvent], src_ip: str | None, details: str) -> Detection:
    info = RULES[rule_id]
    stamped = [e.timestamp for e in events if e.timestamp]
    return Detection(
        rule_id=rule_id, title=title, severity=info.severity, mitre=info.mitre, src_ip=src_ip,
        count=len(events), first_seen=min(stamped) if stamped else None, last_seen=max(stamped) if stamped else None,
        line_numbers=[e.line_no for e in events], samples=[e.raw[:300] for e in events[:MAX_SAMPLES]],
        details=details,
    )


def _burst(events: list[LogEvent], window: timedelta, threshold: int) -> list[LogEvent] | None:
    """Sliding window: return the largest group of events within `window`, if it reaches `threshold`."""
    events = sorted((e for e in events if e.timestamp), key=lambda e: e.timestamp)
    best: list[LogEvent] = []
    start = 0
    for end in range(len(events)):
        while events[end].timestamp - events[start].timestamp > window:
            start += 1
        if end - start + 1 > len(best):
            best = events[start:end + 1]
    return best if len(best) >= threshold else None


def _by_ip(events: list[LogEvent], event_type: str) -> dict[str, list[LogEvent]]:
    groups: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.event_type == event_type and e.src_ip:
            groups[e.src_ip].append(e)
    return groups


# ---------------------------------------------------------------- R-001 / R-002
def ssh_brute_force(events: list[LogEvent]) -> list[Detection]:
    found = []
    for ip, failures in _by_ip(events, AUTH_FAILURE).items():
        burst = _burst(failures, timedelta(minutes=2), 5)
        if burst:
            users = sorted({e.user for e in burst if e.user})[:10]
            found.append(_detection("R-001", f"SSH brute force from {ip}", burst, ip,
                                    f"{len(burst)} failed logins within 2 minutes "
                                    f"({len(failures)} in total). Usernames tried: {', '.join(users)}"))
    return found


def login_after_brute_force(events: list[LogEvent]) -> list[Detection]:
    found = []
    failures = _by_ip(events, AUTH_FAILURE)
    for ip, successes in _by_ip(events, AUTH_SUCCESS).items():
        for ok in successes:
            if ok.timestamp is None:
                continue
            prior = [f for f in failures.get(ip, [])
                     if f.timestamp and timedelta(0) <= ok.timestamp - f.timestamp <= timedelta(minutes=10)]
            if len(prior) >= 5:
                found.append(_detection("R-002", f"Successful login as '{ok.user}' after brute force from {ip}",
                                        [*prior[-4:], ok], ip,
                                        f"{len(prior)} failed attempts in the 10 minutes before a successful login "
                                        f"for user '{ok.user}'. The account may be compromised."))
                break  # one alert per IP is enough
    return found


# ---------------------------------------------------------------- web rules
_TRAVERSAL = re.compile(r"\.\.[/\\]")
_SQLI = re.compile(
    r"union\s+(?:all\s+)?select|'\s*or\s+'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b|sleep\s*\(|benchmark\s*\("
    r"|information_schema|;\s*drop\s+table|'\s*--",
    re.IGNORECASE,
)


def _decoded(path: str) -> str:
    # Decode twice: attackers double-encode (%252e -> %2e -> .) to dodge naive filters.
    return unquote_plus(unquote_plus(path))


def _pattern_rule(events, rule_id, pattern, label) -> list[Detection]:
    groups: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.event_type == HTTP_REQUEST and e.path and pattern.search(_decoded(e.path)):
            groups[e.src_ip or "unknown"].append(e)
    found = []
    for ip, hits in groups.items():
        statuses = sorted({str(e.status) for e in hits if e.status})
        found.append(_detection(rule_id, f"{label} from {ip}", hits, ip,
                                f"{len(hits)} matching request(s). Response codes: {', '.join(statuses) or 'n/a'}. "
                                "A 2xx response may mean the attempt succeeded - verify on the server."))
    return found


def path_traversal(events):
    return _pattern_rule(events, "R-003", _TRAVERSAL, "Path traversal attempt")


def sql_injection(events):
    return _pattern_rule(events, "R-004", _SQLI, "SQL injection attempt")


def web_enumeration(events: list[LogEvent]) -> list[Detection]:
    found = []
    not_found = [e for e in events if e.event_type == HTTP_REQUEST and e.status == 404]
    for ip, hits in _by_ip(not_found, HTTP_REQUEST).items():
        burst = _burst(hits, timedelta(minutes=1), 20)
        if burst:
            found.append(_detection("R-005", f"Web directory enumeration from {ip}", burst, ip,
                                    f"{len(burst)} requests returned 404 within 1 minute "
                                    f"({len(hits)} 404s in total)."))
    return found


LOG_RULES = (ssh_brute_force, login_after_brute_force, path_traversal, sql_injection, web_enumeration)


def run_log_rules(events: list[LogEvent]) -> list[Detection]:
    detections: list[Detection] = []
    for rule in LOG_RULES:
        detections.extend(rule(events))
    return detections
