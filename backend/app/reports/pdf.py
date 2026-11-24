"""Incident report as PDF (ReportLab).

SECURITY NOTE: ReportLab's Paragraph understands a small HTML-like markup
(<b>, <font>, <a href>…). Incident text comes from users and from log files
(attacker-controlled), so EVERY piece of dynamic text is escaped with
`esc()` before it goes into a Paragraph. Otherwise a crafted alert title
could change the report's content or inject links.
"""

import io
from datetime import UTC, datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.schemas.incident import IncidentDetail

ACCENT = colors.HexColor("#0e7490")
SEV_COLORS = {"critical": "#be123c", "high": "#c2410c", "medium": "#a16207", "low": "#0369a1", "info": "#475569"}


def esc(value) -> str:
    """Escape text for ReportLab Paragraph markup and keep line breaks."""
    if value is None or value == "":
        return "-"
    return escape(str(value)).replace("\n", "<br/>")


def _fmt(dt: datetime | None) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if dt else "-"


def _table(rows, widths, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                  ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    t.setStyle(TableStyle(style))
    return t


def build_incident_pdf(inc: IncidentDetail, generated_by: str) -> bytes:
    buf = io.BytesIO()
    generated_at = datetime.now(UTC)
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm,
                            bottomMargin=18 * mm, title=f"Incident report #{inc.id}", author="Mini SOC")
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=ACCENT, fontSize=17)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=ACCENT, fontSize=12, spaceBefore=10)
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)
    mono = ParagraphStyle("mono", parent=small, fontName="Courier")
    warn = ParagraphStyle("warn", parent=body, textColor=colors.HexColor("#7e22ce"),
                          backColor=colors.HexColor("#f3e8ff"), borderPadding=6, spaceAfter=8)

    story = [Paragraph(f"Incident Report #{inc.id}", h1), Paragraph(esc(inc.title), ss["Heading3"])]
    if inc.is_simulated:
        story.append(Paragraph("<b>SIMULATED DATA</b> - this incident was built from demonstration records "
                               "and does not describe a real security event.", warn))

    sev_color = SEV_COLORS.get(inc.severity, "#475569")
    meta = [
        [Paragraph("<b>Severity</b>", small),
         Paragraph(f'<font color="{sev_color}"><b>{esc(inc.severity).upper()}</b></font>', small),
         Paragraph("<b>Status</b>", small), Paragraph(esc(inc.status), small)],
        [Paragraph("<b>Opened</b>", small), Paragraph(_fmt(inc.created_at), small),
         Paragraph("<b>Closed</b>", small), Paragraph(_fmt(inc.closed_at), small)],
        [Paragraph("<b>Created by</b>", small), Paragraph(esc(inc.created_by), small),
         Paragraph("<b>Assignee</b>", small), Paragraph(esc(inc.assignee), small)],
    ]
    story += [_table(meta, [28 * mm, 55 * mm, 28 * mm, 63 * mm], header=False), Spacer(1, 4)]

    story += [Paragraph("1. Executive summary", h2), Paragraph(esc(inc.description), body)]

    # Timeline: alerts and notes merged chronologically.
    events = [(a.detected_at, f"Alert ({a.source}{', ' + a.detection_rule_id if a.detection_rule_id else ''})",
               f"[{a.severity.upper()}] {a.title}") for a in inc.alerts]
    events += [(n.created_at, f"Note by {n.author or '?'}", n.body) for n in inc.notes]
    events += [(e.created_at, f"Evidence by {e.uploaded_by or '?'}", e.original_name or e.description or "")
               for e in inc.evidence]
    events.sort(key=lambda e: e[0])
    story.append(Paragraph("2. Timeline of events", h2))
    if events:
        rows = [["Time (UTC)", "Type", "Detail"]] + [
            [Paragraph(_fmt(t), small), Paragraph(esc(kind), small), Paragraph(esc(text[:800]), small)]
            for t, kind, text in events]
        story.append(_table(rows, [30 * mm, 38 * mm, 106 * mm]))
    else:
        story.append(Paragraph("No timeline entries.", body))

    ips = sorted({ip for a in inc.alerts for ip in (a.src_ip, a.dst_ip) if ip})
    rules = sorted({a.detection_rule_id for a in inc.alerts if a.detection_rule_id})
    story += [Paragraph("3. Affected hosts and indicators", h2),
              Paragraph(f"<b>IP addresses:</b> {esc(', '.join(ips)) if ips else '-'}", body),
              Paragraph(f"<b>Detection rules involved:</b> {esc(', '.join(rules)) if rules else '-'}", body),
              Paragraph(f"<b>Linked alerts:</b> {len(inc.alerts)}", body)]

    story.append(Paragraph("4. Evidence", h2))
    if inc.evidence:
        rows = [["#", "Item", "SHA-256", "Added"]] + [
            [str(e.id), Paragraph(esc(e.original_name or "(description only)") + "<br/>" + esc(e.description), small),
             Paragraph(esc(e.sha256), mono), Paragraph(_fmt(e.created_at), small)] for e in inc.evidence]
        story.append(_table(rows, [10 * mm, 58 * mm, 76 * mm, 30 * mm]))
        story.append(Paragraph("SHA-256 values were computed at upload; recompute them to verify the files are "
                               "unchanged.", small))
    else:
        story.append(Paragraph("No evidence recorded.", body))

    story += [Paragraph("5. Root cause and resolution", h2), Paragraph(esc(inc.resolution), body),
              Paragraph("6. Recommendations", h2), Paragraph(esc(inc.recommendations), body)]

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(18 * mm, 10 * mm, f"Mini SOC · generated {_fmt(generated_at)} by {generated_by} · "
                                            "CONFIDENTIAL - contains security information")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
