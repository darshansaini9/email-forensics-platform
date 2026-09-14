"""
correlation_engine.py
Builds campaign clusters across ALL stored cases by grouping emails that
share at least one IOC (IP, domain, URL, or email address), using
union-find. This is the platform-wide view; case_store.find_cases_sharing_iocs
answers "what's related to THIS one email" while this module answers
"what are ALL the campaigns in the case history".

Deliberately a lightweight graph algorithm over SQLite rows rather than a
graph database - honest tradeoff for a prototype: same conceptual output
(clusters + attribution confidence), zero extra infrastructure.
"""

from dataclasses import dataclass, field
from typing import List, Dict
from core.case_store import get_conn


@dataclass
class Campaign:
    cluster_id: int
    case_ids: List[int] = field(default_factory=list)
    subjects: List[str] = field(default_factory=list)
    shared_ips: List[str] = field(default_factory=list)
    shared_domains: List[str] = field(default_factory=list)
    max_risk_score: int = 0
    attribution_confidence: str = "Low"  # Low | Medium | High


class _UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _confidence_from_overlap(num_shared_ips: int, num_shared_domains: int, cluster_size: int) -> str:
    if cluster_size < 2:
        return "Low"
    score = num_shared_ips * 2 + num_shared_domains
    if score >= 4 and cluster_size >= 3:
        return "High"
    if score >= 1:
        return "Medium"
    return "Low"


def build_campaigns(min_cluster_size: int = 2) -> List[Campaign]:
    """
    Groups all cases in the store into campaign clusters based on shared
    IOCs. Only IP and domain overlap are used to form clusters (URLs and
    emails are noisier / too specific to reliably indicate shared
    infrastructure across a whole campaign), but all shared IOC types are
    reported once a cluster exists.
    """
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT case_id, ioc_type, ioc_value FROM case_iocs WHERE ioc_type IN ('ip','domain')"
        ).fetchall()
        all_cases = {r["id"]: dict(r) for r in conn.execute(
            "SELECT id, filename, subject, risk_score FROM cases"
        ).fetchall()}

    uf = _UnionFind()
    ioc_to_cases: Dict[tuple, set] = {}
    for r in rows:
        key = (r["ioc_type"], r["ioc_value"])
        ioc_to_cases.setdefault(key, set()).add(r["case_id"])
        uf.find(r["case_id"])  # ensure registered

    for key, case_ids in ioc_to_cases.items():
        case_ids = list(case_ids)
        for i in range(1, len(case_ids)):
            uf.union(case_ids[0], case_ids[i])

    clusters: Dict[int, List[int]] = {}
    for case_id in uf.parent:
        root = uf.find(case_id)
        clusters.setdefault(root, []).append(case_id)

    campaigns = []
    cluster_num = 0
    for root, case_ids in clusters.items():
        if len(case_ids) < min_cluster_size:
            continue
        cluster_num += 1

        shared_ips = sorted({
            v for (t, v), cids in ioc_to_cases.items()
            if t == "ip" and len(set(case_ids) & cids) >= 2
        })
        shared_domains = sorted({
            v for (t, v), cids in ioc_to_cases.items()
            if t == "domain" and len(set(case_ids) & cids) >= 2
        })

        subjects = [all_cases[cid]["subject"] for cid in case_ids if cid in all_cases]
        max_risk = max((all_cases[cid]["risk_score"] or 0) for cid in case_ids if cid in all_cases)

        campaigns.append(Campaign(
            cluster_id=cluster_num,
            case_ids=sorted(case_ids),
            subjects=subjects,
            shared_ips=shared_ips,
            shared_domains=shared_domains,
            max_risk_score=max_risk,
            attribution_confidence=_confidence_from_overlap(len(shared_ips), len(shared_domains), len(case_ids)),
        ))

    campaigns.sort(key=lambda c: len(c.case_ids), reverse=True)
    return campaigns
