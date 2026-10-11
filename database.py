from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = PROJECT_ROOT / "data" / "cybermorph.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS phishing_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                risk_level TEXT NOT NULL,
                feature_summary TEXT NOT NULL,
                explanation TEXT NOT NULL
            )
            """
        )


def save_phishing_result(
    url: str,
    prediction: str,
    confidence: float,
    risk_level: str,
    feature_summary: dict[str, Any],
    explanation: str,
) -> None:
    import datetime

    init_db()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO phishing_results (
                timestamp, url, prediction, confidence, risk_level, feature_summary, explanation
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
                url,
                prediction,
                float(confidence),
                risk_level,
                json.dumps(feature_summary, ensure_ascii=False),
                explanation,
            ),
        )


def get_phishing_history(limit: int = 10):
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM phishing_results
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_phishing_summary() -> dict[str, int]:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN prediction = 'phishing' THEN 1 ELSE 0 END) AS phishing,
                SUM(CASE WHEN prediction = 'legitimate' THEN 1 ELSE 0 END) AS legitimate
            FROM phishing_results
            """
        ).fetchone()
    if row is None:
        return {"total": 0, "phishing": 0, "legitimate": 0}
    return {
        "total": int(row["total"] or 0),
        "phishing": int(row["phishing"] or 0),
        "legitimate": int(row["legitimate"] or 0),
    }
