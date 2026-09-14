"""
domain_intel.py
WHOIS-based domain intelligence: registration/creation date, registrar,
and a "recently registered" flag (newly-registered domains are one of
the single strongest phishing signals - most legitimate business domains
are years old, most throwaway phishing domains are days or weeks old).

Requires: pip install python-whois
Degrades gracefully without network/package access, same pattern as
geo_lookup.py and ml_classifier.py - the platform should never crash
just because an enrichment source is unreachable.
"""

import socket
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

NEWLY_REGISTERED_THRESHOLD_DAYS = 90
WHOIS_TIMEOUT_SECONDS = 4


@dataclass
class DomainIntel:
    domain: str
    status: str = "unknown"  # ok | unavailable | error
    registrar: Optional[str] = None
    created_date: Optional[str] = None
    age_days: Optional[int] = None
    is_newly_registered: bool = False
    note: str = ""

    def to_dict(self):
        return asdict(self)


def _first(value):
    """python-whois sometimes returns a list for dates/registrar; normalize to one value."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def lookup_domain(domain: str) -> DomainIntel:
    if not domain:
        return DomainIntel(domain=domain, status="error", note="No domain provided")

    try:
        import whois
    except ImportError:
        return DomainIntel(
            domain=domain,
            status="unavailable",
            note="python-whois not installed - run: pip install python-whois",
        )

    # WHOIS servers can hang rather than error - cap it so one slow lookup
    # never stalls the whole analysis pipeline.
    previous_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(WHOIS_TIMEOUT_SECONDS)
        w = whois.whois(domain)
    except Exception as e:
        return DomainIntel(domain=domain, status="unavailable", note=f"WHOIS lookup failed: {e}")
    finally:
        socket.setdefaulttimeout(previous_timeout)

    created = _first(getattr(w, "creation_date", None))
    registrar = _first(getattr(w, "registrar", None))

    if not created:
        return DomainIntel(
            domain=domain,
            status="unavailable",
            note="WHOIS record returned no creation date (common for privacy-protected or ccTLD domains)",
        )

    if isinstance(created, str):
        try:
            created = datetime.fromisoformat(created)
        except ValueError:
            return DomainIntel(domain=domain, status="error", note="Could not parse WHOIS creation date")

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    age_days = (datetime.now(timezone.utc) - created).days
    newly_registered = age_days < NEWLY_REGISTERED_THRESHOLD_DAYS

    return DomainIntel(
        domain=domain,
        status="ok",
        registrar=str(registrar) if registrar else None,
        created_date=created.date().isoformat(),
        age_days=age_days,
        is_newly_registered=newly_registered,
        note="Domain registered within the last 90 days - common phishing-infrastructure pattern"
             if newly_registered else "",
    )
