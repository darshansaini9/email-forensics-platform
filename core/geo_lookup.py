"""
geo_lookup.py
Resolves an IP address to approximate geolocation + infrastructure
intelligence. Uses ip-api.com's free tier by default (no API key,
45 req/min) - swap in ipinfo.io / MaxMind GeoLite2 / your paid
threat-intel feed for production use by editing PROVIDER_URL below.

Falls back to a clearly-labeled "unavailable" result if there's no network
access, so the rest of the pipeline still runs offline/in a sandboxed demo.

IMPORTANT: proxy, hosting, and trusted_provider are kept as SEPARATE
signals rather than one blanket "suspicious infrastructure" flag. A prior
version of this module conflated them, which meant Google's own outbound
mail servers (correctly classified as "hosting" infrastructure by IP
intelligence, since Google Cloud IS a hosting provider) got flagged the
same way as an actual VPN/proxy relay. See core/trusted_infra.py for the
provider allowlist that fixes this at the risk-scoring layer.
"""

import requests
from dataclasses import dataclass, asdict
from typing import Optional
from core.trusted_infra import is_trusted_provider

PROVIDER_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,proxy,hosting,query"


@dataclass
class GeoResult:
    ip: str
    status: str = "unknown"       # ok | unavailable | error
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    proxy: bool = False              # provider's own proxy/anonymizer flag
    hosting: bool = False            # provider's own datacenter/hosting flag
    trusted_provider: bool = False   # ISP/org matches a known major mail provider (Google, Microsoft, etc.)
    note: str = ""
    disclaimer: str = (
        "GeoIP indicates the network location associated with the sending "
        "infrastructure at the time of transmission. This does not by itself "
        "establish the physical location or identity of the sender - the "
        "infrastructure may be a VPN, proxy, hosting provider, or "
        "compromised system unrelated to the actor's real location."
    )

    @property
    def likely_hosting_or_proxy(self) -> bool:
        """Backward-compatible combined flag, now correctly EXCLUDING
        trusted major providers - hosting infra alone from a known trusted
        mail provider is not itself a red flag."""
        return self.proxy or (self.hosting and not self.trusted_provider)

    def to_dict(self):
        d = asdict(self)
        d["likely_hosting_or_proxy"] = self.likely_hosting_or_proxy
        return d


def lookup_ip(ip: str, timeout: float = 3.0) -> GeoResult:
    if not ip:
        return GeoResult(ip=ip, status="error", note="No IP provided")

    try:
        resp = requests.get(PROVIDER_URL.format(ip=ip), timeout=timeout)
        data = resp.json()
    except Exception as e:
        return GeoResult(
            ip=ip,
            status="unavailable",
            note=f"Geolocation lookup failed (no network access in this "
                 f"environment, or provider unreachable): {e}",
        )

    if data.get("status") != "success":
        return GeoResult(
            ip=ip,
            status="error",
            note=data.get("message", "lookup failed"),
        )

    isp = data.get("isp", "") or ""
    org = data.get("org", "") or ""
    proxy = bool(data.get("proxy"))
    hosting = bool(data.get("hosting"))
    trusted = is_trusted_provider(isp, org)

    if proxy:
        note = "Proxy/anonymization infrastructure detected"
    elif hosting and trusted:
        note = f"Hosting infrastructure, but matches known trusted mail provider ({isp or org})"
    elif hosting:
        note = "Hosting/datacenter infrastructure (not a recognized major mail provider)"
    else:
        note = ""

    return GeoResult(
        ip=ip,
        status="ok",
        country=data.get("country"),
        country_code=data.get("countryCode"),
        region=data.get("regionName"),
        city=data.get("city"),
        isp=isp,
        org=org,
        asn=data.get("as"),
        proxy=proxy,
        hosting=hosting,
        trusted_provider=trusted,
        note=note,
    )
