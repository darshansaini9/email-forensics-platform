"""
auth_checker.py
Extracts SPF / DKIM / DMARC verdicts from an already-received email's
Authentication-Results and Received-SPF headers.

Note: this reads the verdicts the RECEIVING mail server already computed
at delivery time (fast, no DNS calls, works offline). For a from-scratch
re-verification against live DNS records, see verify_live() which is
optional and requires network access + the `checkdmarc` package.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class AuthVerdict:
    spf: str = "none"        # pass | fail | softfail | neutral | none | temperror | permerror
    dkim: str = "none"       # pass | fail | none
    dmarc: str = "none"      # pass | fail | none
    spf_detail: str = ""
    dkim_detail: str = ""
    dmarc_detail: str = ""
    alignment_ok: Optional[bool] = None


def _extract_result(auth_results_text: str, mechanism: str) -> Optional[str]:
    """
    Authentication-Results headers look like:
    mx.google.com; spf=pass (...) smtp.mailfrom=x@y.com;
    dkim=pass header.i=@y.com; dmarc=pass (p=REJECT) header.from=y.com
    """
    pattern = rf"{mechanism}\s*=\s*(\w+)"
    match = re.search(pattern, auth_results_text, re.IGNORECASE)
    return match.group(1).lower() if match else None


def parse_auth_headers(authentication_results_raw, received_spf_raw) -> AuthVerdict:
    verdict = AuthVerdict()
    combined = " ".join(authentication_results_raw)

    spf = _extract_result(combined, "spf")
    dkim = _extract_result(combined, "dkim")
    dmarc = _extract_result(combined, "dmarc")

    if spf:
        verdict.spf = spf
    elif received_spf_raw:
        # fallback: parse legacy Received-SPF header, e.g. "pass (domain ...)"
        rspf_match = re.match(r"^\s*(\w+)", received_spf_raw[0])
        if rspf_match:
            verdict.spf = rspf_match.group(1).lower()

    if dkim:
        verdict.dkim = dkim
    if dmarc:
        verdict.dmarc = dmarc

    verdict.spf_detail = combined
    verdict.dkim_detail = combined
    verdict.dmarc_detail = combined

    # Alignment: DMARC passing is the strongest signal that SPF/DKIM domain
    # actually matches the visible From: domain (not just "some domain").
    if verdict.dmarc == "pass":
        verdict.alignment_ok = True
    elif verdict.dmarc in ("fail", "none") and (verdict.spf == "pass" or verdict.dkim == "pass"):
        # SPF/DKIM can pass for a DIFFERENT domain than the visible From:
        # header (classic spoofing-adjacent trick) - DMARC fail here is a
        # meaningful red flag even if the individual mechanisms passed.
        verdict.alignment_ok = False
    else:
        verdict.alignment_ok = None

    return verdict


def verify_live(domain: str, sender_ip: str = None):
    """
    Optional: re-check SPF/DMARC against live DNS for the claimed sending
    domain. Requires network access and `pip install checkdmarc dnspython`.
    Not used by default in the demo pipeline (keeps it runnable offline),
    but wired in here so it's a one-line swap for a real deployment.
    """
    try:
        import checkdmarc
    except ImportError:
        return {"error": "checkdmarc not installed - run: pip install checkdmarc"}

    try:
        result = checkdmarc.check_domains([domain])
        return result
    except Exception as e:
        return {"error": str(e)}
