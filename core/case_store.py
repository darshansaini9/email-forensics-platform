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
    origin_city TEXT,
    origin_lat REAL,
    origin_lon REAL,
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
        # Lightweight migration: cases.db files created before the threat
        # map / dashboard feature was added won't have these columns yet.
        # SQLite has no "ADD COLUMN IF NOT EXISTS", so check pragma first.
        existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
        for col, coltype in (("origin_city", "TEXT"), ("origin_lat", "REAL"), ("origin_lon", "REAL")):
            if col not in existing_cols:
                conn.execute(f"ALTER TABLE cases ADD COLUMN {col} {coltype}")


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
    origin = report.get("origin") or {}
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO cases
               (filename, analyzed_at, evidence_sha256, subject, from_address,
                from_domain, origin_ip, origin_country, origin_city, origin_lat, origin_lon,
                risk_score, verdict, report_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                filename,
                datetime.now(timezone.utc).isoformat(),
                evidence_sha256,
                report["message"]["subject"],
                report["message"]["from_address"],
                report["message"]["from_domain"],
                origin.get("ip"),
                origin.get("country"),
                origin.get("city"),
                origin.get("lat"),
                origin.get("lon"),
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


# --- Dashboard / Threat Map queries -----------------------------------
# Everything below reads plain columns for speed (no report_json parsing)
# except where a hop-by-hop route is actually needed (get_case_route),
# since that's the one thing not flattened into its own column.

def dashboard_stats():
    """Aggregate counts backing the /dashboard stat cards."""
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS n FROM cases").fetchone()["n"]
        phishing = conn.execute(
            "SELECT COUNT(*) AS n FROM cases WHERE verdict IN ('Likely Phishing', 'High-Risk Fraud')"
        ).fetchone()["n"]
        critical = conn.execute(
            "SELECT COUNT(*) AS n FROM cases WHERE verdict = 'High-Risk Fraud'"
        ).fetchone()["n"]
        avg_score_row = conn.execute("SELECT AVG(risk_score) AS avg FROM cases").fetchone()
        avg_score = round(avg_score_row["avg"], 1) if avg_score_row["avg"] is not None else 0

        verdict_rows = conn.execute(
            "SELECT verdict, COUNT(*) AS n FROM cases GROUP BY verdict"
        ).fetchall()
        verdict_breakdown = {r["verdict"]: r["n"] for r in verdict_rows}

        domain_rows = conn.execute(
            """SELECT from_domain, COUNT(*) AS n FROM cases
               WHERE from_domain IS NOT NULL AND from_domain != ''
               GROUP BY from_domain ORDER BY n DESC LIMIT 5"""
        ).fetchall()

        return {
            "total_scans": total,
            "phishing_detected": phishing,
            "critical_threats": critical,
            "avg_risk_score": avg_score,
            "verdict_breakdown": verdict_breakdown,
            "top_domains": [{"domain": r["from_domain"], "count": r["n"]} for r in domain_rows],
        }


def _time_and_risk_filter(days, risk_level):
    """Shared WHERE-clause builder for the threat-map endpoints."""
    clauses = []
    params = []
    if days:
        clauses.append("analyzed_at >= datetime('now', ?)")
        params.append(f"-{int(days)} days")
    if risk_level:
        if risk_level == "Critical":
            clauses.append("verdict = 'High-Risk Fraud'")
        elif risk_level == "High":
            clauses.append("verdict = 'Likely Phishing'")
        elif risk_level == "Medium":
            clauses.append("verdict = 'Suspicious'")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def map_points(days: int = None, risk_level: str = None, limit: int = 500):
    """
    Origin markers for the threat map. Each stored case contributes at most
    one point (its earliest-external-hop origin) - the hop-by-hop route
    lines are fetched separately per case via get_case_route, since drawing
    every case's full route by default would clutter the aggregate map.
    """
    where, params = _time_and_risk_filter(days, risk_level)
    geo_clause = (where + " AND") if where else " WHERE"
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT id, subject, from_address, origin_city, origin_country,
                       origin_lat, origin_lon, risk_score, verdict, analyzed_at
                FROM cases{geo_clause} origin_lat IS NOT NULL AND origin_lon IS NOT NULL""",
            params,
        ).fetchall()
        points = []
        for r in rows[:limit]:
            points.append({
                "type": "origin",
                "case_id": r["id"],
                "from": r["from_address"],
                "subject": r["subject"],
                "city": r["origin_city"],
                "country": r["origin_country"],
                "lat": r["origin_lat"],
                "lon": r["origin_lon"],
                "risk_score": r["risk_score"],
                "risk_level": _risk_level_label(r["verdict"]),
                "timestamp": r["analyzed_at"],
            })
        return points


def map_routes(days: int = None, risk_level: str = None, limit: int = 200):
    """
    Hop-by-hop routes (the 'thread map') for cases in range, pulled from
    each case's stored report_json since the geolocated hop chain isn't
    flattened into its own column.
    """
    where, params = _time_and_risk_filter(days, risk_level)
    query = f"SELECT id, verdict, report_json FROM cases{where} ORDER BY id DESC LIMIT ?"
    with get_conn() as conn:
        rows = conn.execute(query, (*params, limit)).fetchall()
        routes = []
        for r in rows:
            report = json.loads(r["report_json"])
            hop_geo = report.get("hop_geo") or []
            geolocated = [h for h in hop_geo if h.get("lat") is not None and h.get("lon") is not None]
            if len(geolocated) >= 2:
                is_suspicious = r["verdict"] in ("Likely Phishing", "High-Risk Fraud")
                routes.append({
                    "type": "route",
                    "case_id": r["id"],
                    "hops": [
                        {"lat": h["lat"], "lon": h["lon"], "suspicious": is_suspicious}
                        for h in geolocated
                    ],
                })
        return routes


def _risk_level_label(verdict: str) -> str:
    return {
        "Legitimate": "Safe",
        "Suspicious": "Medium",
        "Likely Phishing": "High",
        "High-Risk Fraud": "Critical",
    }.get(verdict, "Unknown")


def map_stats(days: int = None):
    where, params = _time_and_risk_filter(days, None)
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS n FROM cases{where}", params).fetchone()["n"]
        geo_tagged = conn.execute(
            f"SELECT COUNT(*) AS n FROM cases{(where + ' AND') if where else ' WHERE'} origin_lat IS NOT NULL",
            params,
        ).fetchone()["n"]
        countries = conn.execute(
            f"SELECT COUNT(DISTINCT origin_country) AS n FROM cases{(where + ' AND') if where else ' WHERE'} origin_country IS NOT NULL",
            params,
        ).fetchone()["n"]
        top_countries_rows = conn.execute(
            f"""SELECT origin_country AS country, COUNT(*) AS count, AVG(risk_score) AS avg_risk
                FROM cases{(where + ' AND') if where else ' WHERE'} origin_country IS NOT NULL
                GROUP BY origin_country ORDER BY count DESC LIMIT 10""",
            params,
        ).fetchall()
        return {
            "total_scans": total,
            "geo_tagged": geo_tagged,
            "countries": countries,
            "top_countries": [
                {"country": r["country"], "count": r["count"], "avg_risk": round(r["avg_risk"] or 0, 1)}
                for r in top_countries_rows
            ],
        }


def recent_feed(limit: int = 10):
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT id, subject, from_address, origin_country, risk_score, verdict, analyzed_at
               FROM cases ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [
            {
                "case_id": r["id"],
                "from": r["from_address"],
                "subject": r["subject"],
                "country": r["origin_country"],
                "risk_score": r["risk_score"],
                "risk_level": _risk_level_label(r["verdict"]),
                "verdict": r["verdict"],
                "timestamp": r["analyzed_at"],
            }
            for r in rows
        ]


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
