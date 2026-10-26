from __future__ import annotations

import datetime
import json
import sqlite3
from typing import Any, Optional

from src.config import DB_PATH
from src.risk_scoring import DEFAULT_RISK_BANDS


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
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                target TEXT NOT NULL,
                predicted_class TEXT NOT NULL,
                risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
                severity TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
                evidence_json TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN'
                    CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
                acknowledged_at TEXT,
                resolved_at TEXT
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_alerts_created_at ON security_alerts(created_at)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_alerts_status_severity ON security_alerts(status, severity)"
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
    risk_score: Optional[int] = None,
    risk_evidence: Optional[list[str]] = None,
    recommendation: Optional[str] = None,
) -> int:
    """Insert a new analysis record and return its row ID."""
    init_db()
    if risk_score is not None:
        risk_score = _validate_risk_score(risk_score)
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    details_data = dict(details or {})
    if risk_score is not None:
        details_data.setdefault("risk_score", risk_score)
        details_data.setdefault("risk_severity", DEFAULT_RISK_BANDS.classify(risk_score))
        details_data.setdefault("risk_evidence", risk_evidence or [])
        details_data.setdefault("recommendation", recommendation or "Review the model output and corroborate it with independent security telemetry.")
        details_data.setdefault("score_kind", "model-derived risk index; not a calibrated probability")
    details_str = json.dumps(details_data, ensure_ascii=False)

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
        analysis_id = int(cursor.lastrowid or 0)
        if risk_score is not None:
            _insert_security_alert(
                cursor,
                analysis_id=analysis_id,
                created_at=now_str,
                analysis_type=analysis_type,
                target=input_summary,
                predicted_class=predicted_class,
                risk_score=risk_score,
                evidence=risk_evidence or [],
                recommendation=recommendation or "Review this model-derived alert and correlate it with independent security telemetry.",
            )
        conn.commit()
        return analysis_id


def get_analysis_history(
    limit: int = 50,
    offset: int = 0,
    analysis_type: Optional[str] = None,
    search_query: Optional[str] = None,
    risk_filter: Optional[str] = None,
    analysis_id: Optional[int] = None,
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

    if analysis_id is not None:
        query += " AND id = ?"
        params.append(analysis_id)

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


def _validate_risk_score(risk_score: Any) -> int:
    if isinstance(risk_score, bool):
        raise ValueError("Risk score must be an integer from 0 to 100.")
    try:
        numeric_score = int(risk_score)
    except (TypeError, ValueError) as exc:
        raise ValueError("Risk score must be an integer from 0 to 100.") from exc
    if numeric_score != risk_score or not 0 <= numeric_score <= 100:
        raise ValueError("Risk score must be an integer from 0 to 100.")
    return numeric_score


def _insert_security_alert(
    cursor: sqlite3.Cursor,
    *,
    analysis_id: int,
    created_at: str,
    analysis_type: str,
    target: str,
    predicted_class: str,
    risk_score: int,
    evidence: list[str],
    recommendation: str,
) -> Optional[int]:
    score = _validate_risk_score(risk_score)
    severity = DEFAULT_RISK_BANDS.classify(score)
    if severity == "Low":
        return None

    safe_evidence = [str(item) for item in evidence if item is not None and str(item).strip()]
    cursor.execute(
        """
        INSERT OR IGNORE INTO security_alerts (
            analysis_id, created_at, updated_at, analysis_type, target,
            predicted_class, risk_score, severity, evidence_json, recommendation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            analysis_id,
            created_at,
            created_at,
            str(analysis_type or "unknown").strip().lower(),
            str(target or f"Analysis {analysis_id}").strip(),
            str(predicted_class or "UNKNOWN").strip(),
            score,
            severity,
            json.dumps(safe_evidence, ensure_ascii=False),
            str(recommendation or "Review the model output and corroborate it with independent telemetry.").strip(),
        ),
    )
    row = cursor.execute(
        "SELECT id FROM security_alerts WHERE analysis_id = ?", (analysis_id,)
    ).fetchone()
    return int(row["id"]) if row else None


def create_security_alert(
    analysis_id: int,
    risk_score: int,
    evidence: Optional[list[str]] = None,
    recommendation: Optional[str] = None,
) -> Optional[int]:
    """Create one alert for a saved analysis; duplicate calls are idempotent.

    Scores in the Low band remain in analysis history but do not generate alerts.
    """
    init_db()
    score = _validate_risk_score(risk_score)
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_connection() as conn:
        cursor = conn.cursor()
        analysis = cursor.execute(
            "SELECT analysis_type, input_summary, predicted_class FROM analysis_history WHERE id = ?",
            (analysis_id,),
        ).fetchone()
        if analysis is None:
            raise ValueError(f"Analysis record {analysis_id} does not exist.")
        alert_id = _insert_security_alert(
            cursor,
            analysis_id=analysis_id,
            created_at=now_str,
            analysis_type=analysis["analysis_type"],
            target=analysis["input_summary"],
            predicted_class=analysis["predicted_class"],
            risk_score=score,
            evidence=evidence or [],
            recommendation=recommendation or "Review the model output and corroborate it with independent telemetry.",
        )
        conn.commit()
        return alert_id


def get_security_alerts(
    limit: int = 100,
    offset: int = 0,
    search_query: Optional[str] = None,
    severity: Optional[str] = None,
    analysis_type: Optional[str] = None,
    status: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Return alert records with optional search and exact-match filters."""
    init_db()
    query = "SELECT * FROM security_alerts WHERE 1=1"
    params: list[Any] = []
    if severity and severity.lower() != "all":
        query += " AND LOWER(severity) = ?"
        params.append(severity.lower())
    if analysis_type and analysis_type.lower() != "all":
        query += " AND LOWER(analysis_type) = ?"
        params.append(analysis_type.lower())
    if status and status.lower() != "all":
        query += " AND LOWER(status) = ?"
        params.append(status.lower())
    if search_query and search_query.strip():
        term = f"%{search_query.strip()}%"
        query += " AND (target LIKE ? OR predicted_class LIKE ? OR recommendation LIKE ? OR evidence_json LIKE ?)"
        params.extend([term, term, term, term])
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([max(1, int(limit)), max(0, int(offset))])

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    alerts = []
    for row in rows:
        alert = dict(row)
        try:
            alert["evidence"] = json.loads(alert.pop("evidence_json"))
        except (TypeError, json.JSONDecodeError):
            alert["evidence"] = []
        alerts.append(alert)
    return alerts


def update_security_alert_status(alert_id: int, new_status: str) -> bool:
    """Acknowledge or resolve an alert; repeated transitions are idempotent."""
    normalized = str(new_status or "").strip().upper()
    if normalized not in {"ACKNOWLEDGED", "RESOLVED"}:
        raise ValueError("New alert status must be ACKNOWLEDGED or RESOLVED.")
    init_db()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_connection() as conn:
        cursor = conn.cursor()
        row = cursor.execute("SELECT status FROM security_alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            return False
        current = row["status"]
        if current == normalized or current == "RESOLVED":
            return current == normalized or normalized == "RESOLVED"
        if normalized == "ACKNOWLEDGED" and current != "OPEN":
            return False
        if normalized == "RESOLVED" and current not in {"OPEN", "ACKNOWLEDGED"}:
            return False
        cursor.execute(
            """
            UPDATE security_alerts
            SET status = ?, updated_at = ?,
                acknowledged_at = CASE WHEN ? = 'ACKNOWLEDGED' THEN COALESCE(acknowledged_at, ?) ELSE acknowledged_at END,
                resolved_at = CASE WHEN ? = 'RESOLVED' THEN COALESCE(resolved_at, ?) ELSE resolved_at END
            WHERE id = ?
            """,
            (normalized, now_str, normalized, now_str, normalized, now_str, alert_id),
        )
        conn.commit()
        return cursor.rowcount == 1


def get_security_alert_counts() -> dict[str, int]:
    """Return alert counts by workflow status and severity."""
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT status, severity, COUNT(*) AS count FROM security_alerts GROUP BY status, severity"
        ).fetchall()
    counts = {
        "total": 0,
        "open": 0,
        "acknowledged": 0,
        "resolved": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
    }
    for row in rows:
        status_key = row["status"].lower()
        severity_key = row["severity"].lower()
        count = int(row["count"])
        counts["total"] += count
        counts[status_key] = counts.get(status_key, 0) + count
        counts[severity_key] = counts.get(severity_key, 0) + count
    return counts


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
        cursor.execute("SELECT analysis_type, details_json FROM analysis_history")
        history_details = cursor.fetchall()
        total_flows = 0
        attack_flows = 0
        benign_flows = 0
        risk_scores: list[int] = []
        critical_scores = 0
        for nr in history_details:
            if nr["details_json"]:
                try:
                    d = json.loads(nr["details_json"])
                    if nr["analysis_type"] == "network":
                        total_flows += int(d.get("total_records", 0))
                        attack_flows += int(d.get("attack_records", 0))
                        benign_flows += int(d.get("benign_records", 0))
                    score = d.get("risk_score")
                    if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 100:
                        score_int = int(score)
                        risk_scores.append(score_int)
                        if DEFAULT_RISK_BANDS.classify(score_int) == "Critical":
                            critical_scores += 1
                except Exception:
                    pass

        stats["total_network_flows"] = total_flows
        stats["attack_network_flows"] = attack_flows
        stats["benign_network_flows"] = benign_flows
        stats["scored_analyses"] = len(risk_scores)
        stats["average_risk_score"] = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0
        stats["critical_risk_count"] = critical_scores

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
