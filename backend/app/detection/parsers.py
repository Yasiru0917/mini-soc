"""Parsers for the supported text log formats.

  auth    Linux /var/log/auth.log (sshd), classic syslog or ISO timestamps
  access  Apache / Nginx "combined" or "common" access log
  jsonl   One JSON object per line with normalised field names

Lines a parser doesn't recognise are counted as "skipped", never guessed.
"""

import json
import re
from datetime import UTC, datetime, timedelta

from app.detection.events import (
    AUTH_FAILURE,
    AUTH_SUCCESS,
    HTTP_REQUEST,
    INVALID_USER,
    OTHER,
    LogEvent,
)

MAX_LINE_LENGTH = 8192   # longer lines are truncated (defends against giant lines)
MAX_LINES = 200_000

# ---------------------------------------------------------------- auth.log
# "Nov 24 10:00:01 host sshd[123]: message"  or  "2026-11-24T10:00:01.123+00:00 host sshd[123]: message"
_SYSLOG = re.compile(
    r"^(?:(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))"
    r"\s+(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)
_FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
_ACCEPTED = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
                       r"from (?P<ip>[0-9a-fA-F:.]+)")
_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")


def _syslog_time(m: re.Match, now: datetime) -> datetime | None:
    if m.group("iso"):
        try:
            ts = datetime.fromisoformat(m.group("iso").replace("Z", "+00:00"))
        except ValueError:
            return None
        return ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    # Classic syslog has no year and no time zone. We assume the current year
    # (or last year if that would be in the future) and UTC. Documented limitation.
    try:
        ts = datetime.strptime(f"{now.year} {m.group('mon')} {m.group('day')} {m.group('clock')}",
                               "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None
    if ts > now + timedelta(days=1):
        ts = ts.replace(year=now.year - 1)
    return ts


def parse_auth_line(line_no: int, line: str, now: datetime) -> LogEvent | None:
    m = _SYSLOG.match(line)
    if not m:
        return None
    ts, msg = _syslog_time(m, now), m.group("msg")
    for pattern, event_type in ((_FAILED, AUTH_FAILURE), (_ACCEPTED, AUTH_SUCCESS), (_INVALID, INVALID_USER)):
        hit = pattern.search(msg)
        if hit:
            return LogEvent(line_no, event_type, ts, src_ip=hit.group("ip"), user=hit.group("user"),
                            message=msg[:500], raw=line)
    return LogEvent(line_no, OTHER, ts, message=msg[:500], raw=line)


# ---------------------------------------------------------------- access log
_ACCESS = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]{3,10}) (?P<path>\S+)(?: HTTP/[\d.]+)?" (?P<status>\d{3}) (?P<size>\S+)'
)


def parse_access_line(line_no: int, line: str, _now: datetime) -> LogEvent | None:
    m = _ACCESS.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        ts = None
    user = m.group("user")
    return LogEvent(line_no, HTTP_REQUEST, ts, src_ip=m.group("ip"), user=None if user == "-" else user,
                    method=m.group("method"), path=m.group("path")[:2048], status=int(m.group("status")), raw=line)


# ---------------------------------------------------------------- JSON lines
_JSON_TYPES = {AUTH_FAILURE, AUTH_SUCCESS, INVALID_USER, HTTP_REQUEST}


def parse_json_line(line_no: int, line: str, _now: datetime) -> LogEvent | None:
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    ts = None
    if isinstance(obj.get("timestamp"), str):
        try:
            ts = datetime.fromisoformat(obj["timestamp"].replace("Z", "+00:00"))
            ts = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
        except ValueError:
            ts = None
    event_type = obj.get("event_type") if obj.get("event_type") in _JSON_TYPES else OTHER
    status = obj.get("status")
    return LogEvent(
        line_no, event_type, ts,
        src_ip=str(obj["src_ip"])[:45] if obj.get("src_ip") else None,
        user=str(obj["user"])[:64] if obj.get("user") else None,
        method=str(obj["method"])[:10] if obj.get("method") else None,
        path=str(obj["path"])[:2048] if obj.get("path") else None,
        status=status if isinstance(status, int) else None,
        message=str(obj.get("message", ""))[:500],
        raw=line,
    )


PARSERS = {"auth": parse_auth_line, "access": parse_access_line, "jsonl": parse_json_line}


def detect_format(lines: list[str]) -> str | None:
    """Guess the format from the first non-empty lines: whichever parser understands most."""
    sample = [ln for ln in lines[:50] if ln.strip()][:20]
    if not sample:
        return None
    now = datetime.now(UTC)
    scores = {
        name: sum(1 for i, ln in enumerate(sample) if parser(i, ln, now) is not None)
        for name, parser in PARSERS.items()
    }
    best = max(scores, key=scores.get)
    return best if scores[best] >= max(1, len(sample) // 2) else None


def parse_lines(fmt: str, lines: list[str]) -> tuple[list[LogEvent], int]:
    """Returns (events, skipped_line_count)."""
    parser = PARSERS[fmt]
    now = datetime.now(UTC)
    events, skipped = [], 0
    for i, line in enumerate(lines[:MAX_LINES], start=1):
        line = line.rstrip("\r\n")[:MAX_LINE_LENGTH]
        if not line.strip():
            continue
        event = parser(i, line, now)
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return events, skipped + max(0, len(lines) - MAX_LINES)
