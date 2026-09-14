"""
ioc_extractor.py
Pulls a flat, dedup'd list of indicators of compromise (IPs, domains, URLs,
email addresses) out of headers + body, for the case-management / campaign
correlation view. This is deliberately simple (regex-based) - the value
in a prototype is having a clean, structured IOC list to feed a graph
view or a threat-intel lookup later, not sophisticated extraction logic.
"""

import re
from dataclasses import dataclass, field
from typing import List

DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
IP_REGEX = re.compile(r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)")
URL_REGEX = re.compile(r"https?://[^\s<>\"']+")


@dataclass
class IOCSet:
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)


def _dedupe(items):
    return list(dict.fromkeys(items))


def extract_iocs(parsed_email, geo_ip: str = None) -> IOCSet:
    full_text = " ".join([
        parsed_email.subject or "",
        parsed_email.body_text or "",
        parsed_email.body_html or "",
        parsed_email.from_header or "",
        parsed_email.reply_to or "",
        parsed_email.return_path or "",
    ])

    ips = IP_REGEX.findall(full_text)
    for hop in parsed_email.hops:
        if hop.from_ip:
            ips.append(hop.from_ip)
    if geo_ip:
        ips.append(geo_ip)

    urls = URL_REGEX.findall(full_text)
    emails = EMAIL_REGEX.findall(full_text)

    domains = set()
    if parsed_email.from_domain:
        domains.add(parsed_email.from_domain)
    for url in urls:
        m = re.match(r"https?://([^/]+)", url)
        if m:
            domains.add(m.group(1).lower())
    for e in emails:
        domains.add(e.split("@")[-1].lower())

    return IOCSet(
        ips=_dedupe(ips),
        domains=_dedupe(sorted(domains)),
        urls=_dedupe(urls),
        emails=_dedupe(emails),
    )
