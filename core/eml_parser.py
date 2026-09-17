"""
eml_parser.py
Parses raw .eml files into structured header, hop-chain, and body data.
This is the forensic ingestion layer: everything downstream (auth checking,
geolocation, content analysis) works off the structure produced here.
"""

import re
import ipaddress
import email
from email import policy
from email.parser import BytesParser
from dataclasses import dataclass, field
from typing import List, Optional


IP_REGEX = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
)

# Private/reserved ranges we should not treat as "the attacker's real IP"
# PRIVATE_IP_PATTERNS kept only as a fallback for malformed strings that
# ipaddress.ip_address() can't parse - the real classification now uses
# Python's ipaddress module (see _is_private_ip below), which correctly
# covers RFC1918 private ranges AND the ranges the old regex list missed:
# TEST-NET-1/2/3 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24), CGNAT (100.64.0.0/10), multicast, etc. Treating those
# as "private/non-attributable" matters - a header chain terminating in a
# TEST-NET address is either synthetic/test data or malformed, and should
# never be reported to GeoIP or shown as a real originating IP.
PRIVATE_IP_PATTERNS = [
    re.compile(r"^10\."),
    re.compile(r"^127\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^0\."),
]


@dataclass
class Hop:
    index: int
    raw: str
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    timestamp: Optional[str] = None
    is_private_ip: bool = False


@dataclass
class ParsedEmail:
    subject: str = ""
    from_header: str = ""
    from_display_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    message_id: str = ""
    date: str = ""
    hops: List[Hop] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    attachments: List[str] = field(default_factory=list)
    raw_headers: dict = field(default_factory=dict)
    authentication_results_raw: List[str] = field(default_factory=list)
    received_spf_raw: List[str] = field(default_factory=list)


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        # is_global is False for private, loopback, link-local, multicast,
        # unspecified, AND the reserved/documentation ranges (TEST-NET-1/2/3,
        # CGNAT, etc.) - exactly the set of "not a real routable origin" IPs
        # we want to skip past when looking for the true earliest external hop.
        return not addr.is_global
    except ValueError:
        # Malformed IP string - fall back to the regex patterns rather than crash.
        return any(p.match(ip) for p in PRIVATE_IP_PATTERNS)


def _extract_ips(text: str) -> List[str]:
    return IP_REGEX.findall(text or "")


def _split_display_and_address(from_header: str):
    """Split 'Display Name <user@domain.com>' into parts."""
    match = re.match(r'^\s*"?([^"<]*)"?\s*<?([^<>\s]+@[^<>\s]+)>?\s*$', from_header or "")
    if match:
        display = match.group(1).strip()
        addr = match.group(2).strip()
        return display, addr
    # fallback: maybe it's just an address
    if "@" in (from_header or ""):
        return "", from_header.strip()
    return from_header or "", ""


def parse_received_header(raw: str, index: int) -> Hop:
    """
    Best-effort parse of a single Received: header into structured fields.
    Received headers are famously inconsistent across MTAs, so this is
    intentionally lenient/regex-based rather than a strict grammar parser.
    """
    hop = Hop(index=index, raw=raw)

    from_match = re.search(r"from\s+([^\s]+(?:\s+\([^)]*\))?)", raw, re.IGNORECASE)
    if from_match:
        hop.from_host = from_match.group(1).strip()

    by_match = re.search(r"by\s+([^\s]+)", raw, re.IGNORECASE)
    if by_match:
        hop.by_host = by_match.group(1).strip()

    ips = _extract_ips(raw)
    if ips:
        # heuristic: prefer an IP that appears inside brackets/parens near "from"
        bracketed = re.findall(r"[\[\(]([\d.]+)[\]\)]", raw)
        candidate = bracketed[0] if bracketed else ips[0]
        hop.from_ip = candidate
        hop.is_private_ip = _is_private_ip(candidate)

    ts_match = re.search(r";\s*(.+)$", raw)
    if ts_match:
        hop.timestamp = ts_match.group(1).strip()

    return hop


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    parsed = ParsedEmail()

    parsed.subject = msg.get("Subject", "")
    parsed.from_header = msg.get("From", "")
    parsed.reply_to = msg.get("Reply-To", "")
    parsed.return_path = msg.get("Return-Path", "")
    parsed.to = msg.get("To", "")
    parsed.message_id = msg.get("Message-ID", "")
    parsed.date = msg.get("Date", "")

    display, addr = _split_display_and_address(parsed.from_header)
    parsed.from_display_name = display
    parsed.from_address = addr
    parsed.from_domain = addr.split("@")[-1].lower() if "@" in addr else ""

    # Received headers are returned newest-first by email lib; we reverse
    # so index 0 == earliest hop == closest to true origin.
    received_headers = msg.get_all("Received", [])
    received_headers_chronological = list(reversed(received_headers))
    parsed.hops = [
        parse_received_header(h, i) for i, h in enumerate(received_headers_chronological)
    ]

    parsed.authentication_results_raw = msg.get_all("Authentication-Results", []) or []
    parsed.received_spf_raw = msg.get_all("Received-SPF", []) or []

    for key in msg.keys():
        parsed.raw_headers.setdefault(key, []).append(msg.get(key))

    # Body extraction
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                filename = part.get_filename()
                if filename:
                    parsed.attachments.append(filename)
                continue
            if ctype == "text/plain" and not parsed.body_text:
                try:
                    parsed.body_text = part.get_content()
                except Exception:
                    pass
            elif ctype == "text/html" and not parsed.body_html:
                try:
                    parsed.body_html = part.get_content()
                except Exception:
                    pass
    else:
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if msg.get_content_type() == "text/html":
            parsed.body_html = content
        else:
            parsed.body_text = content

    return parsed


def get_earliest_external_hop(parsed: ParsedEmail) -> Optional[Hop]:
    """
    The single most important forensic value: the earliest hop with a
    public (non-private) IP is the best estimate of the true sending
    infrastructure, since everything after that is internal relay/MTA
    routing within the receiving organization.
    """
    for hop in parsed.hops:
        if hop.from_ip and not hop.is_private_ip:
            return hop
    return None
