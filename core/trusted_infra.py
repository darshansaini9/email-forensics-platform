"""
trusted_infra.py
Reference data for distinguishing "this is Google/Microsoft/Amazon's own
mail infrastructure" from "this is generic/unknown hosting, a VPN, or a
proxy". Without this distinction, the risk engine treats a legitimate
Gmail-sent email the same as one relayed through an anonymous VPS -
both get flagged as "hosting/VPN/proxy infrastructure", which is a real
false-positive generator (see: Google's own outbound mail servers are
correctly classified as "hosting" by IP-intelligence APIs, since Google
Cloud IS a hosting provider - the platform needs to know Google-the-
mail-provider is trustworthy even though Google-the-hosting-company
shows up on the same ASN).

Also used to keep campaign correlation meaningful: two unrelated,
legitimate Gmail users' emails will always share gmail.com/google.com
infrastructure - that overlap is universal, not evidence of a shared
threat actor, so these domains are excluded from campaign clustering.
"""

# Matched against GeoIP's isp/org fields (case-insensitive substring match).
# Deliberately limited to major, well-known mail-sending providers - not
# every cloud host. Being on this list only means "don't penalize this
# infrastructure by default", not "always trust this email" - a message
# claiming to be from one of these but FAILING SPF/DKIM/DMARC alignment
# is still scored as suspicious by the auth-mismatch signal, independent
# of this list.
TRUSTED_MAIL_PROVIDER_KEYWORDS = [
    "google llc", "google inc",
    "microsoft corporation", "microsoft corp",
    "amazon.com", "amazon technologies",
    "yahoo",
    "apple inc",
    "zoho corporation",
    "salesforce.com",  # includes Salesforce-owned ExactTarget/Marketing Cloud sending infra
    "sendgrid",
    "mailchimp", "the rocket science group",  # Mailchimp's legal entity name
    "outlook", "office 365", "microsoft office",
]

# Domain suffixes that are expected to appear across huge numbers of
# unrelated legitimate emails (a shared mail provider's own infrastructure
# domains). Excluded from campaign correlation - matching on these proves
# "both senders use Gmail", not "both emails are from the same threat actor".
COMMON_SHARED_DOMAIN_SUFFIXES = [
    "google.com", "gmail.com", "googlemail.com", "googleusercontent.com",
    "gstatic.com", "googleapis.com", "google-analytics.com",
    "microsoft.com", "outlook.com", "live.com", "office365.com",
    "hotmail.com", "office.com",
    "yahoo.com", "yahoomail.com",
    "apple.com", "icloud.com",
    "amazonaws.com", "amazon.com",
    "sendgrid.net", "mailchimp.com", "salesforce.com", "exacttarget.com",
]


def is_trusted_provider(isp: str, org: str) -> bool:
    combined = f"{isp or ''} {org or ''}".lower()
    return any(kw in combined for kw in TRUSTED_MAIL_PROVIDER_KEYWORDS)


def is_common_shared_domain(domain: str) -> bool:
    domain = (domain or "").lower()
    return any(domain == suf or domain.endswith("." + suf) for suf in COMMON_SHARED_DOMAIN_SUFFIXES)
