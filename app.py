"""
app.py
Flask web application for the AI-Powered Email Threat Detection,
GeoLocation and Forensic Intelligence Platform prototype (SIH26106).

Run:
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000

Pipeline per uploaded .eml:
  1. Parse headers, hop chain, body            (core/eml_parser.py)
  2. SPF/DKIM/DMARC verdicts                    (core/auth_checker.py)
  3. GeoIP + hosting/VPN/proxy flag on origin    (core/geo_lookup.py)
  4. WHOIS / domain age intelligence             (core/domain_intel.py)
  5. Heuristic content analysis (explainable)    (core/content_analyzer.py)
  6. ML/NLP classifier (the "AI" component)       (core/ml_classifier.py)
  7. IOC extraction                               (core/ioc_extractor.py)
  8. Fused fraud score + verdict                   (core/risk_engine.py)
  9. Evidence hash (chain-of-custody)               (core/evidence.py)
  10. Persist as a case + cross-case IOC correlation (core/case_store.py, core/correlation_engine.py)
"""

import json
import io
import re
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for

from core.eml_parser import parse_eml_bytes, get_earliest_external_hop
from core.auth_checker import parse_auth_headers
from core.geo_lookup import lookup_ip, GeoResult
from core.content_analyzer import analyze_content
from core.ioc_extractor import extract_iocs
from core.risk_engine import assess_risk
from core.ml_classifier import classify_text
from core.domain_intel import lookup_domain
from core.evidence import record_evidence
from core import case_store
from core.correlation_engine import build_campaigns
from core.trusted_infra import is_common_shared_domain

app = Flask(__name__)
app.secret_key = "sih26106-prototype-demo-key"  # fine for a hackathon demo; replace for real deployment
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload cap

case_store.init_db()

# Holds the last analyzed report in memory purely so /report/download can
# re-serve the JSON without a DB round trip. The durable copy lives in
# cases.db via case_store - this is just a convenience cache.
LAST_REPORT = {}


def run_pipeline(raw_bytes: bytes, filename: str = "uploaded.eml") -> dict:
    evidence = record_evidence(raw_bytes)

    parsed = parse_eml_bytes(raw_bytes)
    auth_verdict = parse_auth_headers(parsed.authentication_results_raw, parsed.received_spf_raw)

    earliest_hop = get_earliest_external_hop(parsed)
    if earliest_hop and earliest_hop.from_ip:
        geo_result = lookup_ip(earliest_hop.from_ip)
    else:
        geo_result = GeoResult(ip="", status="unavailable", note="No public originating IP found in header chain")

    domain_intel_result = lookup_domain(parsed.from_domain) if parsed.from_domain else None

    content_analysis = analyze_content(
        subject=parsed.subject,
        body_text=parsed.body_text,
        body_html=parsed.body_html,
        display_name=parsed.from_display_name,
        from_domain=parsed.from_domain,
        reply_to=parsed.reply_to,
        return_path=parsed.return_path,
    )

    ml_result = classify_text(parsed.subject, parsed.body_text or parsed.body_html)

    iocs = extract_iocs(parsed, geo_ip=geo_result.ip if geo_result.status == "ok" else None)

    risk = assess_risk(
        auth_verdict=auth_verdict,
        content_analysis=content_analysis,
        geo_result=geo_result,
        parsed_email=parsed,
        num_attachments=len(parsed.attachments),
        ml_result=ml_result,
        domain_intel=domain_intel_result,
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence": {
            "sha256": evidence.sha256,
            "ingested_at": evidence.ingested_at,
            "byte_size": evidence.byte_size,
        },
        "message": {
            "subject": parsed.subject,
            "from_display_name": parsed.from_display_name,
            "from_address": parsed.from_address,
            "from_domain": parsed.from_domain,
            "reply_to": parsed.reply_to,
            "return_path": parsed.return_path,
            "to": parsed.to,
            "message_id": parsed.message_id,
            "date": parsed.date,
            "attachments": parsed.attachments,
        },
        "authentication": {
            "spf": auth_verdict.spf,
            "dkim": auth_verdict.dkim,
            "dmarc": auth_verdict.dmarc,
            "alignment_ok": auth_verdict.alignment_ok,
        },
        "hops": [
            {
                "index": h.index,
                "raw": h.raw,
                "from_host": h.from_host,
                "from_ip": h.from_ip,
                "by_host": h.by_host,
                "timestamp": h.timestamp,
                "is_private_ip": h.is_private_ip,
                "is_earliest_external": earliest_hop is not None and h.index == earliest_hop.index,
            }
            for h in parsed.hops
        ],
        "origin": geo_result.to_dict() if geo_result else None,
        "domain_intel": domain_intel_result.to_dict() if domain_intel_result else None,
        "content_analysis": {
            "score": content_analysis.score,
            "findings": [
                {"category": f.category, "detail": f.detail, "weight": f.weight}
                for f in content_analysis.findings
            ],
            "urls_found": content_analysis.urls_found,
        },
        "ml_classification": {
            "available": ml_result.available,
            "label": ml_result.label,
            "confidence": ml_result.confidence,
            "note": ml_result.note,
            "backend": ml_result.backend,
        },
        "iocs": {
            "ips": iocs.ips,
            "domains": iocs.domains,
            "urls": iocs.urls,
            "emails": iocs.emails,
        },
        "risk_assessment": {
            "score": risk.score,
            "verdict": risk.verdict,
            "factors": [
                {"category": f.category, "detail": f.detail, "weight": f.weight}
                for f in risk.factors
            ],
        },
    }

    case_id = case_store.save_case(
        report,
        filename=filename,
        evidence_sha256=evidence.sha256,
        correlation_iocs=_build_correlation_iocs(iocs, geo_result),
    )
    report["case_id"] = case_id
    report["related_cases"] = case_store.find_cases_sharing_iocs(case_id)

    return report


def _build_correlation_iocs(iocs, geo_result) -> dict:
    """
    Filters the full IOC set down to what's actually meaningful for
    cross-case campaign correlation. Excluded here:
      - Domains that are common shared mail-provider infrastructure
        (gmail.com, google.com, outlook.com, etc.)
      - Email addresses AT those common shared domains (e.g.
        no-reply@accounts.google.com) - matching on the sending domain
        alone already proved nothing; matching on "both emails came
        from a no-reply@ address at Google" proves even less.
      - URLs hosted on those common shared domains.
      - The origin IP, if GeoIP identified it as belonging to a
        recognized trusted provider. Note: this one specifically
        requires a successful live GeoIP lookup to apply - if GeoIP is
        unavailable (no network), the IP is left unfiltered and the
        platform errs toward showing a possible correlation rather than
        silently hiding one it can't actually verify.
    None of this filtering touches what's DISPLAYED in the per-email
    report (report["iocs"] keeps everything) - only what feeds the
    cross-case matching in case_iocs.
    """
    filtered_domains = [d for d in iocs.domains if not is_common_shared_domain(d)]
    filtered_emails = [e for e in iocs.emails if not is_common_shared_domain(e.split("@")[-1])]
    filtered_urls = []
    for u in iocs.urls:
        m = re.match(r"https?://([^/]+)", u)
        host = m.group(1).lower() if m else ""
        if not is_common_shared_domain(host):
            filtered_urls.append(u)

    filtered_ips = list(iocs.ips)
    if geo_result and geo_result.status == "ok" and geo_result.trusted_provider:
        filtered_ips = [ip for ip in filtered_ips if ip != geo_result.ip]

    return {
        "ips": filtered_ips,
        "domains": filtered_domains,
        "urls": filtered_urls,
        "emails": filtered_emails,
    }


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded = request.files.get("eml_file")
    if not uploaded or uploaded.filename == "":
        flash("Please choose a .eml file to analyze.")
        return redirect(url_for("index"))

    raw_bytes = uploaded.read()
    try:
        report = run_pipeline(raw_bytes, filename=uploaded.filename)
    except Exception as e:
        flash(f"Could not parse this file as an email: {e}")
        return redirect(url_for("index"))

    LAST_REPORT["data"] = report
    LAST_REPORT["filename"] = uploaded.filename
    return render_template("report.html", report=report, source_filename=uploaded.filename)


@app.route("/analyze/sample/<sample_name>", methods=["GET"])
def analyze_sample(sample_name):
    import os
    path = os.path.join("sample_emails", f"{sample_name}.eml")
    if not os.path.exists(path):
        flash("Unknown sample.")
        return redirect(url_for("index"))
    with open(path, "rb") as f:
        raw_bytes = f.read()
    report = run_pipeline(raw_bytes, filename=f"{sample_name}.eml")
    LAST_REPORT["data"] = report
    LAST_REPORT["filename"] = f"{sample_name}.eml"
    return render_template("report.html", report=report, source_filename=f"{sample_name}.eml")


@app.route("/cases", methods=["GET"])
def list_cases():
    cases = case_store.list_cases()
    return render_template("cases.html", cases=cases)


@app.route("/cases/<int:case_id>", methods=["GET"])
def view_case(case_id):
    case = case_store.get_case(case_id)
    if not case:
        flash("Case not found.")
        return redirect(url_for("list_cases"))
    report = case["report"]
    report["case_id"] = case_id
    report["related_cases"] = case_store.find_cases_sharing_iocs(case_id)
    return render_template("report.html", report=report, source_filename=case["filename"])


@app.route("/campaigns", methods=["GET"])
def campaigns_view():
    campaigns = build_campaigns()
    return render_template("campaigns.html", campaigns=campaigns)


@app.route("/report/download", methods=["GET"])
def download_report():
    if "data" not in LAST_REPORT:
        flash("No report available yet - analyze an email first.")
        return redirect(url_for("index"))
    buf = io.BytesIO(json.dumps(LAST_REPORT["data"], indent=2).encode("utf-8"))
    buf.seek(0)
    fname = f"forensic_report_{LAST_REPORT.get('filename', 'email')}.json"
    return send_file(buf, mimetype="application/json", as_attachment=True, download_name=fname)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """JSON API endpoint - lets you wire this into another dashboard/tool."""
    uploaded = request.files.get("eml_file")
    if not uploaded:
        return jsonify({"error": "no file provided, expected form field 'eml_file'"}), 400
    raw_bytes = uploaded.read()
    try:
        report = run_pipeline(raw_bytes, filename=uploaded.filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(report)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
