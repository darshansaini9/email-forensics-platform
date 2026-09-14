"""
case_store.py
Persists every analyzed email as a "case" in SQLite so the platform can
do cross-email correlation (the "Identity Correlation and Attribution
Support" component) instead of only ever looking at one email in
isolation. Also the minimal starting point for chain-of-custody: each
case stores the SHA-256 of the original raw .eml bytes alongside the
analysis, so the evidence and the report can be tied back together.

This is intentionally SQLite + stdlib only - zero setup required for a
hackathon demo. Swap for Postgres in a real deployment.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from contextlib import contextmanager

DB_PATH = os.environ.get("EFP_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "cases.db"))


SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    analyzed_at TEXT,
    evidence_sha256 TEXT,
    subject TEXT,
    from_address TEXT,
    from_domain TEXT,
    origin_ip TEXT,
    origin_country TEXT,
    risk_score INTEGER,
    verdict TEXT,
    report_json TEXT
);

CREATE TABLE IF NOT EXISTS case_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL,      -- ip | domain | url | email
    ioc_value TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases (id)
);

CREATE INDEX IF NOT EXISTS idx_case_iocs_value ON case_iocs (ioc_type, ioc_value);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def save_case(report: dict, filename: str, evidence_sha256: str, correlation_iocs: dict = None) -> int:
    """
    correlation_iocs, if given, overrides which IOCs are indexed for
    cross-case correlation (case_iocs table) - the full IOC set still
    lives in report_json regardless. Callers filter out common shared
    infrastructure (e.g. gmail.com, Google's own IPs) before passing
    this, so two unrelated legitimate emails that both happen to go
    through Gmail don't get clustered into a fake "campaign". See
    core/trusted_infra.py and app.py's run_pipeline for the filtering.
    """
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO cases
               (filename, analyzed_at, evidence_sha256, subject, from_address,
                from_domain, origin_ip, origin_country, risk_score, verdict, report_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                filename,
                datetime.now(timezone.utc).isoformat(),
                evidence_sha256,
                report["message"]["subject"],
                report["message"]["from_address"],
                report["message"]["from_domain"],
                report["origin"]["ip"] if report.get("origin") else None,
                report["origin"].get("country") if report.get("origin") else None,
                report["risk_assessment"]["score"],
                report["risk_assessment"]["verdict"],
                json.dumps(report),
            ),
        )
        case_id = cur.lastrowid

        iocs = correlation_iocs if correlation_iocs is not None else report.get("iocs", {})
        rows = []
        for ip in iocs.get("ips", []):
            rows.append((case_id, "ip", ip))
        for d in iocs.get("domains", []):
            rows.append((case_id, "domain", d))
        for u in iocs.get("urls", []):
            rows.append((case_id, "url", u))
        for e in iocs.get("emails", []):
            rows.append((case_id, "email", e))
        if rows:
            conn.executemany(
                "INSERT INTO case_iocs (case_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
                rows,
            )
        return case_id


def list_cases(limit: int = 100):
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT id, filename, analyzed_at, subject, from_address, from_domain,
                      origin_ip, origin_country, risk_score, verdict
               FROM cases ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_case(case_id: int):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["report"] = json.loads(result.pop("report_json"))
        return result


def find_cases_sharing_iocs(case_id: int):
    """
    Returns other cases that share at least one IOC (IP, domain, URL, or
    email address) with the given case, along with which values overlap.
    This is the "campaign correlation" lookup - deliberately a plain SQL
    self-join rather than a graph database, so it needs zero extra infra
    for the prototype while still answering the question a graph view
    would answer: "what else is connected to this email?"
    """
    with get_conn() as conn:
        this_case_iocs = conn.execute(
            "SELECT ioc_type, ioc_value FROM case_iocs WHERE case_id = ?", (case_id,)
        ).fetchall()
        if not this_case_iocs:
            return []

        related = {}
        for row in this_case_iocs:
            matches = conn.execute(
                """SELECT ci.case_id, ci.ioc_type, ci.ioc_value, c.filename, c.subject,
                          c.verdict, c.risk_score, c.analyzed_at
                   FROM case_iocs ci
                   JOIN cases c ON c.id = ci.case_id
                   WHERE ci.ioc_type = ? AND ci.ioc_value = ? AND ci.case_id != ?""",
                (row["ioc_type"], row["ioc_value"], case_id),
            ).fetchall()
            for m in matches:
                key = m["case_id"]
                if key not in related:
                    related[key] = {
                        "case_id": m["case_id"],
                        "filename": m["filename"],
                        "subject": m["subject"],
                        "verdict": m["verdict"],
                        "risk_score": m["risk_score"],
                        "analyzed_at": m["analyzed_at"],
                        "shared_iocs": [],
                    }
                related[key]["shared_iocs"].append({"type": m["ioc_type"], "value": m["ioc_value"]})

        return sorted(related.values(), key=lambda r: len(r["shared_iocs"]), reverse=True)
