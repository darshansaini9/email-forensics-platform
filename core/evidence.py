"""
evidence.py
Minimal chain-of-custody support: hashes the raw, untouched .eml bytes
at ingestion time. Storing this hash alongside the case (see
core/case_store.py) means the analyzed report can always be tied back
to a specific, verifiable copy of the original evidence - if the .eml
file is later re-hashed and the digest matches, you've proven it hasn't
been altered since analysis.

This is intentionally minimal (hash + timestamp), not a full
evidence-management system. A real deployment would add: who
uploaded/accessed each case, signed/append-only audit log, and
retention/access-control policy - noted in the README as next steps.
"""

import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass


@dataclass
class EvidenceRecord:
    sha256: str
    ingested_at: str
    byte_size: int


def record_evidence(raw_bytes: bytes) -> EvidenceRecord:
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return EvidenceRecord(
        sha256=digest,
        ingested_at=datetime.now(timezone.utc).isoformat(),
        byte_size=len(raw_bytes),
    )
