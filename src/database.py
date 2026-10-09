from __future__ import annotations

import datetime
import json
import sqlite3
from typing import Any, Optional

from src.config import DB_PATH


def get_connection() -> sqlite3.Connection:
    """Return a thread-safe connection to the SQLite database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize database tables with parameterized schemas."""
    with get_connection() as conn:
        cursor = conn.cursor()
        # Analysis history table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                input_summary TEXT NOT NULL,
                predicted_class TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                probability REAL,
                model_name TEXT NOT NULL,
                result_summary TEXT NOT NULL,
                details_json TEXT
            )
            """
        )

        # Model evaluation / training runs table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS model_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_type TEXT NOT NULL,
                model_name TEXT NOT NULL,
                dataset_name TEXT NOT NULL,
                training_timestamp TEXT NOT NULL,
                accuracy REAL NOT NULL,
                precision REAL NOT NULL,
                recall REAL NOT NULL,
                f1_score REAL NOT NULL,
                metadata_json TEXT
            )
            """
        )
        conn.commit()


def save_analysis(
    analysis_type: str,
    input_summary: str,
    predicted_class: str,
    risk_level: str,
    probability: Optional[float],
    model_name: str,
    result_summary: str,
    details: Optional[dict[str, Any]] = None,
) -> int:
    """Insert a new analysis record and return its row ID."""
    init_db()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    details_str = json.dumps(details or {}, ensure_ascii=False)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO analysis_history (
                timestamp, analysis_type, input_summary, predicted_class,
                risk_level, probability, model_name, result_summary, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_str,
                analysis_type,
                input_summary,
                predicted_class,
                risk_level,
                float(probability) if probability is not None else None,
                model_name,
                result_summary,
                details_str,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid or 0)


def get_analysis_history(
    limit: int = 50,
    offset: int = 0,
    analysis_type: Optional[str] = None,
    search_query: Optional[str] = None,
    risk_filter: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Retrieve filtered analysis history records."""
    init_db()
    query = "SELECT * FROM analysis_history WHERE 1=1"
    params: list[Any] = []

    if analysis_type and analysis_type != "All":
        query += " AND analysis_type = ?"
        params.append(analysis_type.lower())

    if risk_filter and risk_filter != "All":
        query += " AND LOWER(risk_level) = ?"
        params.append(risk_filter.lower())

    if search_query and search_query.strip():
        query += " AND (input_summary LIKE ? OR result_summary LIKE ?)"
        term = f"%{search_query.strip()}%"
        params.extend([term, term])

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_connection() as conn:
        cursor = conn.cursor()
        rows = cursor.execute(query, params).fetchall()
        results = []
        for row in rows:
            record = dict(row)
            if record.get("details_json"):
                try:
                    record["details"] = json.loads(record["details_json"])
                except Exception:
                    record["details"] = {}
            results.append(record)
        return results


def delete_analysis_record(record_id: int) -> bool:
    """Delete a specific analysis record by ID."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM analysis_history WHERE id = ?", (record_id,))
        conn.commit()
        return cursor.rowcount > 0


def clear_all_history() -> int:
    """Clear all analysis records from history."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM analysis_history")
        deleted = cursor.rowcount
        conn.commit()
        return deleted


def get_overview_stats() -> dict[str, Any]:
    """Calculate aggregated security overview metrics from persistent records."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()

        # Counts by analysis type
        cursor.execute(
            """
            SELECT
                COUNT(*) as total_records,
                SUM(CASE WHEN analysis_type = 'phishing' THEN 1 ELSE 0 END) as total_phishing,
                SUM(CASE WHEN analysis_type = 'phishing' AND LOWER(predicted_class) = 'phishing' THEN 1 ELSE 0 END) as malicious_phishing,
                SUM(CASE WHEN analysis_type = 'phishing' AND LOWER(predicted_class) = 'legitimate' THEN 1 ELSE 0 END) as legitimate_phishing,
                SUM(CASE WHEN analysis_type = 'network' THEN 1 ELSE 0 END) as total_network_runs,
                SUM(CASE WHEN LOWER(risk_level) = 'high' THEN 1 ELSE 0 END) as high_risk_count,
                SUM(CASE WHEN LOWER(risk_level) = 'medium' THEN 1 ELSE 0 END) as medium_risk_count,
                SUM(CASE WHEN LOWER(risk_level) = 'low' THEN 1 ELSE 0 END) as low_risk_count
            FROM analysis_history
            """
        )
        row = cursor.fetchone()

        stats = {
            "total_analyses": int(row["total_records"] or 0),
            "total_phishing": int(row["total_phishing"] or 0),
            "malicious_phishing": int(row["malicious_phishing"] or 0),
            "legitimate_phishing": int(row["legitimate_phishing"] or 0),
            "total_network_runs": int(row["total_network_runs"] or 0),
            "high_risk_count": int(row["high_risk_count"] or 0),
            "medium_risk_count": int(row["medium_risk_count"] or 0),
            "low_risk_count": int(row["low_risk_count"] or 0),
        }

        # Calculate network flow totals from details_json
        cursor.execute("SELECT details_json FROM analysis_history WHERE analysis_type = 'network'")
        net_rows = cursor.fetchall()
        total_flows = 0
        attack_flows = 0
        benign_flows = 0
        for nr in net_rows:
            if nr["details_json"]:
                try:
                    d = json.loads(nr["details_json"])
                    total_flows += int(d.get("total_records", 0))
                    attack_flows += int(d.get("attack_records", 0))
                    benign_flows += int(d.get("benign_records", 0))
                except Exception:
                    pass

        stats["total_network_flows"] = total_flows
        stats["attack_network_flows"] = attack_flows
        stats["benign_network_flows"] = benign_flows

        return stats


def save_model_run(
    model_type: str,
    model_name: str,
    dataset_name: str,
    accuracy: float,
    precision: float,
    recall: float,
    f1_score: float,
    metadata: Optional[dict[str, Any]] = None,
) -> int:
    """Record a model training/evaluation run."""
    init_db()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    meta_str = json.dumps(metadata or {}, ensure_ascii=False)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO model_runs (
                model_type, model_name, dataset_name, training_timestamp,
                accuracy, precision, recall, f1_score, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                model_type,
                model_name,
                dataset_name,
                now_str,
                float(accuracy),
                float(precision),
                float(recall),
                float(f1_score),
                meta_str,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid or 0)


def get_latest_model_run(model_type: str) -> Optional[dict[str, Any]]:
    """Retrieve the most recent model evaluation run for a given type."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        row = cursor.execute(
            """
            SELECT * FROM model_runs
            WHERE model_type = ?
            ORDER BY id DESC LIMIT 1
            """,
            (model_type,),
        ).fetchone()
        if not row:
            return None
        record = dict(row)
        if record.get("metadata_json"):
            try:
                record["metadata"] = json.loads(record["metadata_json"])
            except Exception:
                record["metadata"] = {}
        return record


def get_all_model_runs(model_type: Optional[str] = None) -> list[dict[str, Any]]:
    """Retrieve all model evaluation runs."""
    init_db()
    query = "SELECT * FROM model_runs"
    params = []
    if model_type:
        query += " WHERE model_type = ?"
        params.append(model_type)
    query += " ORDER BY id DESC"

    with get_connection() as conn:
        cursor = conn.cursor()
        rows = cursor.execute(query, params).fetchall()
        results = []
        for row in rows:
            record = dict(row)
            if record.get("metadata_json"):
                try:
                    record["metadata"] = json.loads(record["metadata_json"])
                except Exception:
                    record["metadata"] = {}
            results.append(record)
        return results
