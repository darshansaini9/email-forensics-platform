"""
pdf_report.py
Renders the same forensic report dict used by templates/report.html and
the /report/download JSON endpoint into a printable PDF, for cases where
an analyst needs something to attach to a ticket, print, or hand to
someone who doesn't have access to the dashboard.

This does not replace the JSON export (/report/download) - the JSON
report remains the complete, machine-readable artifact (full IOC lists,
raw hop data, everything needed to feed another tool). The PDF is a
human-readable summary of the same underlying report dict: same fields,
same verdict, same scores, just laid out for reading/printing instead of
parsing.

Kept as its own module (like every other core/*.py file) so the Flask
routes in app.py stay thin, and so this can be reused from a script or a
different frontend without touching the analysis pipeline.
"""

import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)

# Verdict -> accent color, mirrors the v-legit / v-suspicious / v-phishing /
# v-fraud bands in static/style.css so the PDF and the dashboard agree
# visually on how "bad" a verdict looks.
VERDICT_COLORS = {
    "Legitimate": colors.HexColor("#2f9e6e"),
    "Suspicious": colors.HexColor("#c98a1c"),
    "Likely Phishing": colors.HexColor("#d9622b"),
    "High-Risk Fraud": colors.HexColor("#c0394f"),
}
DEFAULT_ACCENT = colors.HexColor("#555555")

PILL_PASS = colors.HexColor("#2f9e6e")
PILL_FAIL = colors.HexColor("#c0394f")
PILL_WARN = colors.HexColor("#c98a1c")
PILL_NEUTRAL = colors.HexColor("#7a7a7a")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name="ReportTitle", parent=ss["Title"], fontSize=18, spaceAfter=2))
    ss.add(ParagraphStyle(name="Meta", parent=ss["Normal"], fontSize=9, textColor=colors.HexColor("#666666")))
    ss.add(ParagraphStyle(name="Section", parent=ss["Heading2"], fontSize=12, spaceBefore=14, spaceAfter=6,
                           textColor=colors.HexColor("#222222")))
    ss.add(ParagraphStyle(name="KVKey", parent=ss["Normal"], fontSize=8.5, textColor=colors.HexColor("#666666")))
    ss.add(ParagraphStyle(name="KVVal", parent=ss["Normal"], fontSize=9.5))
    ss.add(ParagraphStyle(name="Finding", parent=ss["Normal"], fontSize=9.5, leftIndent=6))
    ss.add(ParagraphStyle(name="Empty", parent=ss["Normal"], fontSize=9.5, textColor=colors.HexColor("#888888"),
                           fontName="Helvetica-Oblique"))
    ss.add(ParagraphStyle(name="Footer", parent=ss["Normal"], fontSize=8, textColor=colors.HexColor("#888888")))
    return ss


def _pill_color(value, positive="pass"):
    if value is True or value == positive:
        return PILL_PASS
    if value is False:
        return PILL_FAIL
    if value in ("none", None):
        return PILL_NEUTRAL
    return PILL_FAIL


def _kv_table(rows, styles, col_widths=(120, 300)):
    """rows: list of (label, value-string-or-Paragraph)"""
    data = []
    for label, value in rows:
        if not isinstance(value, Paragraph):
            value = Paragraph(str(value) if value not in (None, "") else "\u2014", styles["KVVal"])
        data.append([Paragraph(label, styles["KVKey"]), value])
    t = Table(data, colWidths=[col_widths[0], col_widths[1]])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#eeeeee")),
    ]))
    return t


def _findings_block(findings, styles, empty_text):
    if not findings:
        return Paragraph(empty_text, styles["Empty"])
    rows = []
    for f in findings:
        weight = f.get("weight", "")
        category = f.get("category", "")
        detail = f.get("detail", "")
        text = f"<b>+{weight}</b> &nbsp; <b>{category}</b> &mdash; {detail}"
        rows.append(Paragraph(text, styles["Finding"]))
        rows.append(Spacer(1, 3))
    return rows


def _chips_line(items, styles):
    if not items:
        return Paragraph("none", styles["Empty"])
    return Paragraph(", ".join(str(i) for i in items), styles["KVVal"])


def build_pdf_report(report: dict, source_filename: str = "email") -> bytes:
    """Render `report` (the same dict passed to templates/report.html and
    returned by /report/download as JSON) into a PDF and return the raw
    bytes. Caller is responsible for wrapping the bytes (e.g. in a
    send_file/BytesIO response)."""
    styles = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Forensic Report - {source_filename}",
    )
    story = []

    message = report.get("message", {}) or {}
    auth = report.get("authentication", {}) or {}
    origin = report.get("origin", {}) or {}
    content = report.get("content_analysis", {}) or {}
    risk = report.get("risk_assessment", {}) or {}
    domain_intel = report.get("domain_intel", {}) or {}
    ml = report.get("ml_classification", {}) or {}
    iocs = report.get("iocs", {}) or {}
    hops = report.get("hops", []) or []
    evidence = report.get("evidence") or {}
    related_cases = report.get("related_cases") or []

    verdict = risk.get("verdict", "Unknown")
    score = risk.get("score", "?")
    accent = VERDICT_COLORS.get(verdict, DEFAULT_ACCENT)

    # --- Header -----------------------------------------------------
    story.append(Paragraph("Forensic Report", styles["ReportTitle"]))
    meta_bits = [f"Source: {source_filename}", f"Generated: {report.get('generated_at', '\u2014')}"]
    if report.get("case_id"):
        meta_bits.append(f"Case #{report['case_id']}")
    story.append(Paragraph(" &middot; ".join(meta_bits), styles["Meta"]))
    story.append(Spacer(1, 10))

    # --- Verdict band -------------------------------------------------
    band = Table(
        [[Paragraph(f"<font size=22><b>{score}</b></font>", styles["Normal"]),
          Paragraph(f"<font size=13 color='white'><b>{verdict}</b></font><br/>"
                    f"<font size=8.5 color='white'>Fraud confidence score out of 100, fused from "
                    f"authentication, origin, content and structural signals</font>", styles["Normal"])]],
        colWidths=[60, 400],
    )
    band.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), accent),
        ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 14),
        ("LEFTPADDING", (1, 0), (1, 0), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(band)
    story.append(Spacer(1, 14))

    # --- Message ------------------------------------------------------
    story.append(Paragraph("Message", styles["Section"]))
    msg_rows = [
        ("Subject", message.get("subject") or "\u2014"),
        ("From", f"{message.get('from_display_name', '')} <{message.get('from_address', '')}>"),
        ("From domain", message.get("from_domain") or "\u2014"),
        ("Reply-To", message.get("reply_to") or "\u2014"),
        ("Return-Path", message.get("return_path") or "\u2014"),
        ("Message-ID", message.get("message_id") or "\u2014"),
        ("Date", message.get("date") or "\u2014"),
    ]
    if evidence:
        msg_rows.append(("Evidence SHA-256", Paragraph(evidence.get("sha256", "\u2014"),
                                                         ParagraphStyle(name="mono", parent=styles["KVVal"], fontSize=7.5,
                                                                        fontName="Courier"))))
    if message.get("attachments"):
        msg_rows.append(("Attachments", ", ".join(message["attachments"])))
    story.append(_kv_table(msg_rows, styles))

    # --- Authentication -------------------------------------------------
    story.append(Paragraph("Authentication", styles["Section"]))
    spf, dkim, dmarc = auth.get("spf"), auth.get("dkim"), auth.get("dmarc")
    align = auth.get("alignment_ok")
    align_text = "aligned" if align is True else ("mismatch" if align is False else "inconclusive")
    story.append(_kv_table([
        ("SPF", str(spf)),
        ("DKIM", str(dkim)),
        ("DMARC", str(dmarc)),
        ("Alignment", align_text),
    ], styles))

    # --- Probable source infrastructure --------------------------------
    story.append(Paragraph("Probable source infrastructure", styles["Section"]))
    if origin.get("status") == "ok":
        rows = [
            ("Origin IP", origin.get("ip") or "\u2014"),
            ("GeoIP estimate", f"{origin.get('city', '')}, {origin.get('region', '')}, {origin.get('country', '')}"),
            ("ISP / Org", origin.get("isp", "") + (f" / {origin['org']}" if origin.get("org") and origin.get("org") != origin.get("isp") else "")),
            ("ASN", origin.get("asn") or "\u2014"),
            ("Proxy", "detected" if origin.get("proxy") else "not detected"),
            ("Hosting/cloud", "yes" if origin.get("hosting") else "no"),
            ("Trusted provider", "yes \u2014 recognized mail provider" if origin.get("trusted_provider") else "not recognized"),
        ]
        story.append(_kv_table(rows, styles))
        if origin.get("note"):
            story.append(Paragraph(origin["note"], styles["Empty"]))
        if origin.get("disclaimer"):
            story.append(Spacer(1, 2))
            story.append(Paragraph(origin["disclaimer"], styles["Empty"]))
    else:
        story.append(Paragraph(origin.get("note", "No origin data available."), styles["Empty"]))

    # --- Content analysis -------------------------------------------------
    story.append(Paragraph(f"Content analysis \u2014 heuristic ({content.get('score', 0)}/100)", styles["Section"]))
    story.extend(_ensure_list(_findings_block(content.get("findings"), styles, "No content-based indicators detected.")))

    # --- Relay / hop chain --------------------------------------------------
    story.append(Paragraph(f"Relay / hop chain ({len(hops)} hop{'s' if len(hops) != 1 else ''})", styles["Section"]))
    if hops:
        for h in hops:
            bits = [f"Hop {h.get('index')}"]
            if h.get("from_host"):
                bits.append(f"from {h['from_host']}")
            if h.get("by_host"):
                bits.append(f"by {h['by_host']}")
            line = " \u2014 ".join(bits)
            if h.get("from_ip"):
                line += f" [{h['from_ip']}]"
            tags = []
            if h.get("is_earliest_external"):
                tags.append("earliest external hop")
            if h.get("is_private_ip"):
                tags.append("private IP")
            if tags:
                line += "  (" + ", ".join(tags) + ")"
            story.append(Paragraph(line, styles["Finding"]))
        story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("No Received headers found in this message.", styles["Empty"]))

    # --- Risk factors -------------------------------------------------------
    story.append(Paragraph(f"Risk factors ({len(risk.get('factors') or [])})", styles["Section"]))
    story.extend(_ensure_list(_findings_block(risk.get("factors"), styles,
                                               "No risk factors detected \u2014 message appears clean based on available signals.")))

    # --- Domain intelligence -------------------------------------------------
    story.append(Paragraph("Domain intelligence", styles["Section"]))
    if domain_intel.get("status") == "ok":
        story.append(_kv_table([
            ("Domain", domain_intel.get("domain") or "\u2014"),
            ("Registered", f"{domain_intel.get('created_date', '\u2014')} ({domain_intel.get('age_days', '?')} days ago)"),
            ("Registrar", domain_intel.get("registrar") or "\u2014"),
            ("Flag", "newly registered" if domain_intel.get("is_newly_registered") else "no flag"),
        ], styles))
    else:
        story.append(Paragraph(domain_intel.get("note", "WHOIS lookup not available in this environment."), styles["Empty"]))

    # --- ML/NLP classifier -------------------------------------------------
    story.append(Paragraph("ML/NLP classifier", styles["Section"]))
    if ml.get("available"):
        rows = [
            ("Label", ml.get("label") or "\u2014"),
            ("Confidence", f"{(ml.get('confidence') or 0) * 100:.0f}%"),
        ]
        if ml.get("backend"):
            rows.append(("Model", "Local sklearn (offline)" if ml["backend"] == "sklearn-local" else "Transformer"))
        story.append(_kv_table(rows, styles))
        if ml.get("note"):
            story.append(Paragraph(ml["note"], styles["Empty"]))
    else:
        note = ml.get("note") if ml else "ML classifier not available."
        story.append(Paragraph(f"{note} The fraud score above is currently based on heuristic and header/origin signals only.",
                                styles["Empty"]))

    # --- Campaign correlation -------------------------------------------------
    if related_cases:
        story.append(Paragraph(f"Campaign correlation \u2014 {len(related_cases)} related case(s)", styles["Section"]))
        for rc in related_cases:
            shared = ", ".join(f"{s.get('type')}: {s.get('value')}" for s in rc.get("shared_iocs", []))
            text = (f"<b>{rc.get('verdict')} \u00b7 {rc.get('risk_score')}/100</b> &mdash; "
                    f"Case #{rc.get('case_id')} \u2014 {rc.get('subject') or rc.get('filename')}<br/>"
                    f"<font size=8.5 color='#777777'>Shared: {shared}</font>")
            story.append(Paragraph(text, styles["Finding"]))
            story.append(Spacer(1, 3))

    # --- Extracted indicators (IOCs) -------------------------------------------------
    story.append(Paragraph("Extracted indicators (IOCs)", styles["Section"]))
    ioc_rows = [
        (f"IP addresses ({len(iocs.get('ips', []))})", _chips_line(iocs.get("ips"), styles)),
        (f"Domains ({len(iocs.get('domains', []))})", _chips_line(iocs.get("domains"), styles)),
        (f"URLs ({len(iocs.get('urls', []))})", _chips_line(iocs.get("urls"), styles)),
        (f"Email addresses ({len(iocs.get('emails', []))})", _chips_line(iocs.get("emails"), styles)),
    ]
    story.append(_kv_table(ioc_rows, styles, col_widths=(140, 320)))

    # --- Footer -----------------------------------------------------------
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#dddddd")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This score is a heuristic prototype output for demonstration purposes \u2014 not a substitute "
        "for analyst review or legal/evidentiary certification.", styles["Footer"]))

    doc.build(story)
    return buf.getvalue()


def _ensure_list(x):
    """_findings_block returns either a single Paragraph (empty case) or a
    list of flowables; normalize to a list so callers can always .extend()."""
    return x if isinstance(x, list) else [x]
