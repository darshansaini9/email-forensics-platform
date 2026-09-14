"""
content_analyzer.py
Heuristic + lightweight NLP analysis of subject/body text for social
engineering and impersonation patterns. Deliberately rule-based (not a
trained model) so the prototype runs instantly with zero training data
and no external ML dependency - swap in a fine-tuned classifier later
(see README) without changing the interface this module exposes.
"""

import re
import difflib
from dataclasses import dataclass, field
from typing import List


URGENCY_PHRASES = [
    "act now", "immediate action", "urgent", "verify your account",
    "suspended", "unauthorized access", "click here immediately",
    "failure to respond", "account will be closed", "final notice",
    "your account has been limited", "confirm your identity",
    "within 24 hours", "expire", "restricted", "unusual activity",
]

CREDENTIAL_HARVEST_PHRASES = [
    "confirm your password", "verify your password", "update your billing",
    "login to your account", "re-enter your credentials", "security check",
    "verify your identity", "reset your password immediately",
]

BEC_PHRASES = [
    "wire transfer", "change of bank details", "urgent payment",
    "invoice attached", "purchase gift cards", "confidential transaction",
    "new payment instructions", "process this payment", "kindly treat as urgent",
]

GENERIC_GREETINGS = ["dear customer", "dear user", "dear valued", "dear sir/madam", "dear account holder"]

# Third-party Email Service Providers whose bounce/return-path domains are
# EXPECTED to differ from the sending organization's own domain - this is
# normal, widespread industry practice for transactional/bulk mail (Amazon
# SES, SendGrid, etc. all use their own bounce-handling infrastructure), not
# evidence of spoofing. Distinct from TRUSTED_MAIL_PROVIDER_KEYWORDS (which
# matches GeoIP ISP/org strings) - this list matches domain suffixes seen in
# Return-Path/Reply-To headers themselves.
TRUSTED_ESP_BOUNCE_DOMAIN_SUFFIXES = [
    "amazonses.com", "sendgrid.net", "sparkpostmail.com", "mailgun.org",
    "mailgun.net", "postmarkapp.com", "mandrillapp.com", "mcsv.net",  # Mailchimp bounce domain
    "sendinblue.com", "constantcontact.com", "campaign-archive.com",
]


def is_trusted_esp_bounce_domain(domain: str) -> bool:
    domain = (domain or "").lower()
    return any(domain == suf or domain.endswith("." + suf) for suf in TRUSTED_ESP_BOUNCE_DOMAIN_SUFFIXES)


# A small list of commonly-impersonated brands for domain lookalike checks.
# Extend this with your organization's own domain + frequently-spoofed partners.
KNOWN_BRAND_DOMAINS = [
    "google.com", "microsoft.com", "paypal.com", "amazon.com", "apple.com",
    "facebook.com", "bankofamerica.com", "chase.com", "netflix.com",
    "irs.gov", "dhl.com", "fedex.com",
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".work", ".zip", ".click", ".info", ".loan", ".gq", ".tk"]

URL_REGEX = re.compile(r"https?://[^\s<>\"']+")


@dataclass
class ContentFinding:
    category: str
    detail: str
    weight: int  # contribution to risk score


@dataclass
class ContentAnalysis:
    findings: List[ContentFinding] = field(default_factory=list)
    urls_found: List[str] = field(default_factory=list)
    score: int = 0  # 0-100, content-only sub-score


def _check_display_name_domain_mismatch(display_name: str, from_domain: str) -> List[ContentFinding]:
    findings = []
    if not display_name or not from_domain:
        return findings

    lowered = display_name.lower()
    for brand in KNOWN_BRAND_DOMAINS:
        brand_name = brand.split(".")[0]
        if brand_name in lowered and brand not in from_domain:
            findings.append(ContentFinding(
                category="Impersonation",
                detail=f"Display name references '{brand_name}' but sending domain is "
                       f"'{from_domain}', not '{brand}'",
                weight=25,
            ))
    return findings


def _check_domain_lookalike(from_domain: str) -> List[ContentFinding]:
    findings = []
    if not from_domain:
        return findings
    for brand in KNOWN_BRAND_DOMAINS:
        if from_domain == brand:
            continue
        ratio = difflib.SequenceMatcher(None, from_domain, brand).ratio()
        if ratio > 0.80:
            findings.append(ContentFinding(
                category="Domain lookalike",
                detail=f"Sending domain '{from_domain}' is suspiciously similar to "
                       f"known brand domain '{brand}' (similarity {ratio:.0%})",
                weight=20,
            ))
    for tld in SUSPICIOUS_TLDS:
        if from_domain.endswith(tld):
            findings.append(ContentFinding(
                category="Suspicious TLD",
                detail=f"Sending domain uses an uncommon/high-abuse TLD ({tld})",
                weight=8,
            ))
    return findings


def _check_phrase_list(text: str, phrases: List[str], category: str, weight_each: int) -> List[ContentFinding]:
    findings = []
    lowered = (text or "").lower()
    hits = [p for p in phrases if p in lowered]
    if hits:
        findings.append(ContentFinding(
            category=category,
            detail=f"Detected phrase(s): {', '.join(hits[:5])}",
            weight=min(weight_each * len(hits), weight_each * 3),
        ))
    return findings


def _extract_domain_from_address(value: str) -> str:
    """Pulls the domain out of a header value like 'Name <user@domain>',
    '<user@domain>', or a bare 'user@domain'."""
    if not value:
        return ""
    m = re.search(r"[\w.+-]+@([\w.-]+)", value)
    return m.group(1).lower() if m else ""


def _same_organization(domain_a: str, domain_b: str) -> bool:
    """True if one domain is a subdomain of the other (e.g.
    'bounces.google.com' vs 'google.com' - legitimately the same sender's
    infrastructure), so we don't flag normal bounce/subdomain patterns as
    a mismatch."""
    if not domain_a or not domain_b:
        return True  # nothing to compare, don't flag
    return domain_a == domain_b or domain_a.endswith("." + domain_b) or domain_b.endswith("." + domain_a)


def _check_reply_return_path_mismatch(from_domain: str, reply_to: str, return_path: str) -> List[ContentFinding]:
    """
    Classic BEC/phishing pattern: the visible From: claims one identity,
    but Reply-To or Return-Path points somewhere unrelated - so a reply
    (or a bounce) goes to the attacker's real mailbox, not the domain
    being impersonated. This is a distinct signal from SPF/DKIM/DMARC
    (which only validate the From: domain's authorization) and from
    display-name impersonation (which only looks at the visible name) -
    a message can pass all of those and still redirect replies elsewhere.
    """
    findings = []
    reply_domain = _extract_domain_from_address(reply_to)
    return_domain = _extract_domain_from_address(return_path)

    if reply_domain and not _same_organization(reply_domain, from_domain):
        if is_trusted_esp_bounce_domain(reply_domain):
            findings.append(ContentFinding(
                category="Reply-To — third-party ESP",
                detail=f"Reply-To domain '{reply_domain}' belongs to a recognized email "
                       f"service provider - normal for transactional/bulk mail, not "
                       f"treated as a risk signal",
                weight=0,
            ))
        else:
            findings.append(ContentFinding(
                category="Reply-To mismatch",
                detail=f"Reply-To domain '{reply_domain}' differs from the From: domain "
                       f"'{from_domain}' - a reply would go to a different, unrelated "
                       f"domain than the claimed sender",
                weight=15,
            ))
    if return_domain and not _same_organization(return_domain, from_domain):
        if is_trusted_esp_bounce_domain(return_domain):
            findings.append(ContentFinding(
                category="Return-Path — third-party ESP",
                detail=f"Return-Path domain '{return_domain}' belongs to a recognized "
                       f"email service provider ({return_domain}) - third-party bounce "
                       f"handling is standard practice for transactional/bulk mail, not "
                       f"treated as a risk signal",
                weight=0,
            ))
        else:
            findings.append(ContentFinding(
                category="Return-Path mismatch",
                detail=f"Return-Path domain '{return_domain}' differs from the From: "
                       f"domain '{from_domain}' - bounces would be routed to a different "
                       f"domain than the claimed sender",
                weight=10,
            ))
    return findings


def analyze_content(subject: str, body_text: str, body_html: str,
                     display_name: str, from_domain: str,
                     reply_to: str = "", return_path: str = "") -> ContentAnalysis:
    analysis = ContentAnalysis()
    full_text = f"{subject}\n{body_text}\n{body_html}"

    analysis.findings.extend(_check_phrase_list(full_text, URGENCY_PHRASES, "Urgency/pressure language", 8))
    analysis.findings.extend(_check_phrase_list(full_text, CREDENTIAL_HARVEST_PHRASES, "Credential harvesting cue", 15))
    analysis.findings.extend(_check_phrase_list(full_text, BEC_PHRASES, "Business email compromise pattern", 20))
    analysis.findings.extend(_check_phrase_list(full_text, GENERIC_GREETINGS, "Generic/non-personalized greeting", 5))
    analysis.findings.extend(_check_display_name_domain_mismatch(display_name, from_domain))
    analysis.findings.extend(_check_domain_lookalike(from_domain))
    analysis.findings.extend(_check_reply_return_path_mismatch(from_domain, reply_to, return_path))

    urls = URL_REGEX.findall(full_text)
    analysis.urls_found = list(dict.fromkeys(urls))  # dedupe, preserve order

    # Flag links whose displayed anchor text differs from the actual href
    # (classic obfuscation) - simple heuristic on raw HTML.
    if body_html:
        anchor_matches = re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', body_html, re.IGNORECASE)
        for href, anchor_text in anchor_matches:
            anchor_text_clean = anchor_text.strip()
            if anchor_text_clean.startswith("http") and href.strip() != anchor_text_clean:
                if anchor_text_clean.split("/")[2] if "//" in anchor_text_clean else False:
                    pass
            if re.match(r"^https?://", anchor_text_clean) and anchor_text_clean not in href:
                analysis.findings.append(ContentFinding(
                    category="Obfuscated link",
                    detail=f"Displayed link text '{anchor_text_clean[:50]}' does not match actual "
                           f"destination '{href[:60]}'",
                    weight=20,
                ))

    analysis.score = min(sum(f.weight for f in analysis.findings), 100)
    return analysis
