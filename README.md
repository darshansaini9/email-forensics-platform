# Email Forensic Intelligence Platform — SIH26106 Prototype

A working prototype for **"AI-Powered Email Threat Detection, GeoLocation and
Forensic Intelligence Platform"**. Upload a raw `.eml` file and it parses the
header chain, checks SPF/DKIM/DMARC, geolocates the earliest external sending
hop, scans content for phishing/BEC patterns, extracts IOCs, and fuses all of
that into one fraud confidence score with a downloadable forensic report.

## Quick start

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. Click one of the two bundled samples to see it
run instantly, or upload your own `.eml` file (export one from Gmail:
open an email → ⋮ → "Show original" → "Download original").

## How each problem-statement component is implemented

| Problem statement component | File | What it does |
|---|---|---|
| Email Header and Protocol Analysis | `core/eml_parser.py`, `core/auth_checker.py` | Parses every `Received:` header into a structured hop chain (host, IP, timestamp), reads `Authentication-Results`/`Received-SPF` for SPF/DKIM/DMARC verdicts, flags alignment mismatches |
| Origin Traceability and Location Analysis | `core/eml_parser.py::get_earliest_external_hop`, `core/geo_lookup.py` | Walks the hop chain to find the earliest **public** IP (skips internal/private relay hops), geolocates it, flags hosting/VPN/proxy infrastructure. Reported as "probable source infrastructure" with an explicit disclaimer, not "attacker location" — GeoIP identifies infrastructure, not identity |
| Fraudulent Email Detection Engine | `core/content_analyzer.py` (heuristic) + `core/ml_classifier.py` (ML) | Two layers, shown separately in the dashboard: an explainable rule-based engine (urgency language, BEC patterns, impersonation, domain lookalikes, obfuscated links) plus a trained ML classifier (`core/ml_classifier.py`) — the actual AI/ML component. On by default, no setup: trains a small local TF-IDF + Logistic Regression model from bundled examples in under a second on first run, then runs fully offline. Both feed the fused score |
| Origin Traceability — domain side | `core/domain_intel.py` | WHOIS-based domain age lookup; flags recently-registered sending domains (a strong phishing signal), degrades gracefully without `python-whois` or network access |
| Identity Correlation and Attribution Support | `core/ioc_extractor.py`, `core/case_store.py`, `core/correlation_engine.py` | Extracts IOCs per message, persists every analyzed email as a case in SQLite, and clusters cases that share an IP/domain into **campaigns** with an attribution-confidence tier (Low/Medium/High) via union-find — a lightweight stand-in for graph-DB correlation with the same output shape |
| Alerting, Dashboard, Forensic Reporting | `app.py`, `templates/report.html`, `templates/cases.html`, `templates/campaigns.html` | Per-email dashboard, case history across all analyzed emails, campaign correlation view, and a downloadable JSON forensic report (`/report/download`) |
| Privacy, Legal, and Compliance Safeguards | `core/evidence.py` | Every analyzed `.eml` gets a SHA-256 hash recorded at ingestion time and stored with its case — the minimal starting point for chain-of-custody (proves the evidence wasn't altered after analysis). See "Next steps" below for what a full deployment still needs here. |

## Architecture

```
.eml upload
     │
     ▼
evidence.py ──► SHA-256 hash + timestamp (chain-of-custody record)
     │
     ▼
eml_parser.py  ──► structured hops, headers, body, attachments
     │
     ├──► auth_checker.py     ──► SPF/DKIM/DMARC verdict + alignment
     ├──► geo_lookup.py        ──► origin IP → country/city/ISP/hosting-flag
     ├──► domain_intel.py       ──► WHOIS domain age → newly-registered flag
     ├──► content_analyzer.py    ──► heuristic phishing/BEC/impersonation findings
     ├──► ml_classifier.py        ──► local trained ML classifier (offline, on by default)
     └──► ioc_extractor.py         ──► IPs / domains / URLs / emails
                │
                ▼
        risk_engine.py  ──► fused 0–100 score + verdict + explanation
                │
                ├──► case_store.py       ──► persists as a case (SQLite)
                └──► correlation_engine.py ──► clusters cases sharing IOCs into campaigns
                │
                ▼
        Flask dashboard + case history + campaign view + JSON report
```

Each module is independent and returns plain dataclasses — you can call
`core/risk_engine.py::assess_risk()` directly from a script, a batch job,
or swap the Flask UI for a FastAPI service without touching the analysis
logic.

## What's a real implementation vs. a demo shortcut (be upfront about this to judges)

- **SPF/DKIM/DMARC**: reads the verdict the *receiving* mail server already
  computed (fast, offline-friendly). `core/auth_checker.py::verify_live()`
  is stubbed in for re-checking against live DNS via `checkdmarc` — worth
  enabling for the final demo if you have network access, since it lets you
  analyze headers even when the original receiving server didn't stamp
  Authentication-Results.
- **Geolocation**: uses `ip-api.com`'s free tier (45 req/min, no key). Swap
  `PROVIDER_URL` in `core/geo_lookup.py` for MaxMind GeoLite2 (offline
  database, no rate limit) before a real deployment. Reported as "probable
  source infrastructure" with an explicit non-attribution disclaimer, never
  as an attacker's physical location.
- **Detection engine**: two layers by design, not one. `content_analyzer.py`
  is deliberately rule-based — transparent, needs zero training data, fast
  to demo, and gives an analyst a *reason* for every point in the score.
  `ml_classifier.py` is the actual AI/ML component: a TF-IDF + Logistic
  Regression classifier trained on bundled examples (`core/ml_training_data.py`)
  — trains itself in under a second on first run, caches to
  `models/phishing_classifier.joblib`, and then runs fully offline with zero
  network dependency. This is a deliberate choice over a Hugging Face
  transformer for demo reliability: a transformer needs to download
  ~500MB-2GB of weights on first run, which is a real liability if your
  network is slow or unavailable right when judges are watching. If you
  want the transformer instead for a non-demo deployment, set
  `USE_TRANSFORMER_BACKEND = True` in `core/ml_classifier.py` and
  `pip install transformers torch` — same `MLResult` shape either way, so
  nothing downstream needs to change. The bundled training set (~95
  examples) is intentionally small and hand-curated for a hackathon
  timeline, not a substitute for a large labeled corpus (e.g. the Nazario
  phishing corpus + Enron ham corpus) in production — say this plainly if
  a judge asks about dataset size.
- **Identity correlation / campaign clustering**: implemented via SQLite +
  union-find (`core/case_store.py`, `core/correlation_engine.py`), not a
  graph database. Every analyzed email becomes a "case"; cases sharing an
  IP or sending domain get clustered into a campaign with a Low/Medium/High
  attribution-confidence tier. This is a legitimate architectural choice for
  a prototype — same conceptual output as a Neo4j-backed graph (clusters +
  confidence), zero extra infrastructure. If you have time, swap the
  clustering query in `correlation_engine.py::build_campaigns()` for an
  actual graph DB without touching anything upstream.
- **Chain-of-custody**: `core/evidence.py` hashes the raw `.eml` bytes at
  ingestion and stores the SHA-256 with the case — enough to prove evidence
  wasn't altered after analysis. Still missing for a full deployment: an
  append-only access log (who viewed which case, when), retention policy,
  and access-controlled storage. Say this plainly if asked — it's a
  reasonable "phase 2" scope, not a project-breaking gap.
- **DNS/WHOIS intelligence**: `core/domain_intel.py` covers domain
  registration age (a strong, cheap phishing signal) via `python-whois`.
  Deeper DNS record analysis (MX/TXT fingerprinting, hosting-provider
  clustering beyond what GeoIP already flags) isn't implemented — reasonable
  to name as a next step if asked.

## Changelog: trusted-infrastructure fixes

A real-world test against an actual Gmail-sourced "account recovered"
email surfaced two false-positive bugs, now fixed:

1. **Legitimate Google/Microsoft/Amazon mail was scored as risky** because
   their own sending infrastructure is correctly classified as "hosting" by
   IP-intelligence APIs (Google Cloud IS a hosting provider) — the risk
   engine treated that the same as an anonymous VPN/proxy relay. Fixed via
   `core/trusted_infra.py`: proxy, hosting, and trusted-provider are now
   three separate signals (`core/geo_lookup.py`), and the risk engine only
   penalizes hosting infrastructure when it does NOT match a recognized
   major mail provider. When it does, the report shows an explicit
   zero-weight "Infrastructure reputation: trusted, no adjustment" factor
   instead of silently doing nothing — so the reasoning is visible, not
   hidden.
2. **Two unrelated legitimate Gmail users got clustered into a fake
   "campaign"** because both emails shared `gmail.com`/Google's sending IP —
   universal overlap, not evidence of a shared threat actor. Fixed in
   `app.py::_build_correlation_iocs()`: domains, emails, and URLs on common
   shared mail-provider infrastructure (see `COMMON_SHARED_DOMAIN_SUFFIXES`
   in `core/trusted_infra.py`) are excluded from what feeds cross-case
   correlation, and a trusted-provider IP is excluded too once GeoIP
   confirms it. Genuine phishing campaigns (sharing an unrecognized
   domain/IP) still correlate correctly — verified with two BEC sample
   emails sharing `hostingcloud-relay.net`.

Both fixes were verified with the Flask test client, not just by reading
the code: the actual Google-recovery-email scenario now scores 0/Legitimate
instead of 18, and two independently-addressed Google emails no longer
appear as "related cases" of each other.

## Changelog: scoring and IP-classification fixes

A second round of testing (against a synthetic phishing email using
documentation/test IP ranges) surfaced three more real issues:

1. **TEST-NET/documentation IPs (192.0.2.0/24, 198.51.100.0/24,
   203.0.113.0/24, RFC 5737) weren't recognized as non-routable.**
   `eml_parser.py`'s private-IP check was a hand-written regex list
   covering only RFC1918 + loopback + link-local. Replaced with Python's
   `ipaddress` module (`addr.is_global`), which correctly and comprehensively
   covers private, reserved, loopback, link-local, multicast, and
   documentation ranges in one call. A header chain that never leaves
   documentation-IP space now correctly reports "No public originating IP
   found" instead of sending a reserved-range IP to GeoIP and getting back
   a confusing "error".
2. **The risk score under-counted messages with multiple independent
   content indicators.** `risk_engine.py` was collapsing all content
   findings into a single factor capped at 40 points, regardless of how
   much evidence was actually found - so a message with five strong,
   independent indicators scored the same as one with two weak ones.
   Fixed by scoring each finding as its own factor (the overall 0-100
   score is still globally capped, so this doesn't risk runaway scores -
   it just stops silently discarding evidence).
3. **Reply-To / Return-Path domain mismatch wasn't checked at all** - a
   classic BEC/phishing pattern where the visible From: claims one
   identity but replies/bounces route to a completely different domain.
   This is distinct from SPF/DKIM/DMARC (which only validates the From:
   domain's authorization) and from display-name impersonation (which only
   looks at the visible name) - a message can pass both of those and still
   redirect replies elsewhere. Added as a new check in
   `content_analyzer.py::_check_reply_return_path_mismatch()`, with a
   same-organization exemption (e.g. `bounces.google.com` vs `google.com`)
   so legitimate subdomain bounce patterns aren't flagged.

Net effect on the synthetic phishing test case: score went from 50/100
("Likely Phishing") to 84/100 ("High-Risk Fraud") - not by inflating
weights to hit a target number, but because two of those points are
genuinely new evidence the platform wasn't checking before, and the third
was previously-detected evidence that a scoring bug was throwing away.
Regression-tested against all prior samples (phishing_sample.eml still
scores 100/High-Risk Fraud, legit_sample.eml still scores 0/Legitimate,
the Google-recovery false-positive fix still holds) to confirm nothing
else broke.

## Changelog: third-party ESP false positive

Round 3 of testing caught a regression I'd introduced in round 2: the new
Reply-To/Return-Path mismatch check didn't account for legitimate
third-party Email Service Providers (Amazon SES, SendGrid, Mailchimp,
etc.), where the Return-Path pointing to the ESP's own bounce-handling
domain instead of the sending organization's domain is normal, widespread
industry practice for transactional/bulk mail - not evidence of spoofing.
A test email sent "via Amazon SES" was getting a false +10 penalty.

Fixed with `TRUSTED_ESP_BOUNCE_DOMAIN_SUFFIXES` in `content_analyzer.py`
(amazonses.com, sendgrid.net, mailgun.org, postmarkapp.com, mcsv.net, and
similar). When Reply-To/Return-Path lands on a recognized ESP domain, the
report now shows a zero-weight "third-party ESP, not a risk signal" note
instead of a penalty - same transparency pattern as the earlier
trusted-mail-provider fix. Verified the fix doesn't affect genuine
detection: the actual phishing sample's Reply-To
(`protonmail-secure.xyz`, not a recognized ESP) still correctly triggers
the mismatch factor.

## Changelog: ML classifier now actually runs, offline, by default

The dashboard's ML panel previously always said "unavailable - run: pip
install transformers torch", which is a bad look for an "AI-Powered"
project during judging. Rather than just installing the heavy transformer
dependency (real risk: a live multi-GB model download from Hugging Face
right when judges are watching, if the network hiccups), replaced it with
a locally-trained scikit-learn classifier (TF-IDF + Logistic Regression)
that ships with the repo and works out of the box:

- `core/ml_training_data.py` — ~95 bundled, hand-curated examples split
  across phishing/BEC patterns and legitimate email patterns.
- `core/ml_classifier.py` — trains the model on first run (under a second),
  caches it to `models/phishing_classifier.joblib`, and every run after
  that loads instantly from disk. No network call, no download, no API key.
- Verified on all existing test cases (phishing_sample.eml, legit_sample.eml,
  the uploaded suspicious-email test, and several held-out phrasings not in
  the training set) - all correctly classified.
- Caught and fixed one real generalization gap during testing: the first
  training set didn't have enough legitimate "account security notification"
  examples (e.g. "your account was recovered successfully, secure your
  account if this wasn't you"), so the model initially flagged the
  legitimate Google-recovery email as phishing purely on shared vocabulary
  ("secure your account"). Fixed by adding contrastive legitimate examples
  covering that pattern - re-verified correct after retraining.
- The transformer backend is still available as a documented upgrade path
  (`USE_TRANSFORMER_BACKEND = True` in `core/ml_classifier.py`) for a
  non-demo deployment where a first-run download is acceptable.

## Reference repos this design pulled from
- [keraattin/EmailAnalyzer](https://github.com/keraattin/EmailAnalyzer) — Authentication-Results parsing pattern
- [z0m31en7/WhatMail](https://github.com/z0m31en7/WhatMail) — header field coverage reference
- [cmacha2/phishing-detection-py](https://github.com/cmacha2/phishing-detection-py) — drop-in replacement if you want a trained model instead of the rule-based content analyzer

## Project layout

```
app.py                      Flask routes + pipeline orchestration
core/
  eml_parser.py              .eml → structured headers/hops/body
  auth_checker.py             SPF/DKIM/DMARC verdict parsing
  geo_lookup.py                IP → geolocation + proxy/hosting/trusted-provider signals
  trusted_infra.py              major-provider allowlist + common-shared-domain list
  domain_intel.py                WHOIS domain age lookup
  content_analyzer.py            phishing/BEC content heuristics (explainable)
  ml_classifier.py                 local trained ML classifier (TF-IDF + LogReg, offline)
  ml_training_data.py               bundled training examples for the classifier
  ioc_extractor.py                   IP/domain/URL/email extraction
  evidence.py                          SHA-256 evidence hashing (chain-of-custody)
  case_store.py                          SQLite case persistence
  correlation_engine.py                    campaign clustering across cases
  risk_engine.py                             fuses everything into one score
templates/
  index.html                  upload page
  report.html                 forensic dashboard (per-email)
  cases.html                  case history across all analyzed emails
  campaigns.html               cross-email campaign correlation view
static/style.css              visual design
sample_emails/
  phishing_sample.eml         BEC/phishing demo (scores ~85-100, High-Risk Fraud)
  phishing_sample_2.eml       shares IP/domain with phishing_sample.eml — analyze
                               both to see campaign correlation (/campaigns) light up
  legit_sample.eml            clean demo (scores 0, Legitimate)
cases.db                      created on first run (SQLite) — delete to reset case history
```
