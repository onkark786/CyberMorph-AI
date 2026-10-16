from __future__ import annotations

from pathlib import Path

import pytest

import src.database as database
from src.risk_scoring import RiskBands, assess_network_risk, assess_phishing_risk


@pytest.fixture

def isolated_alert_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "alerts_test.sqlite3")
    database.init_db()


def test_risk_band_boundaries_and_custom_bands() -> None:
    bands = RiskBands()
    assert [bands.classify(value) for value in (0, 24, 25, 49, 50, 74, 75, 100)] == [
        "Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"
    ]
    custom = RiskBands(low_max=9, medium_max=39, high_max=79)
    assert custom.classify(10) == "Medium"
    with pytest.raises(ValueError):
        RiskBands(low_max=40, medium_max=30, high_max=80)


def test_phishing_score_uses_model_class_output() -> None:
    result = assess_phishing_risk("phishing", 0.836)
    assert result["risk_score"] == 84
    assert result["risk_severity"] == "Critical"
    assert "not a calibrated probability" in result["score_kind"]
    assert "0.8360" in result["risk_evidence"][0]


def test_network_score_uses_predictions_and_probability_outputs() -> None:
    result = assess_network_risk(["ATTACK", "BENIGN"], [0.8, 0.1])
    assert result["risk_score"] == 49
    assert result["risk_severity"] == "Medium"
    assert "1 of 2 flows" in result["risk_evidence"][0]

    prediction_only = assess_network_risk(["ATTACK", "BENIGN", "BENIGN"])
    assert prediction_only["risk_score"] == 33
    assert "No attack-class probabilities" in prediction_only["risk_evidence"][1]


def test_alert_creation_is_persisted_deduplicated_and_filtered(
    isolated_alert_database: None,
) -> None:
    analysis_id = database.save_analysis(
        analysis_type="phishing",
        input_summary="https://credential-check.example",
        predicted_class="PHISHING",
        risk_level="High",
        probability=0.86,
        model_name="Test model",
        result_summary="Model classified the URL as phishing.",
        risk_score=86,
        risk_evidence=["Phishing-class model output: 0.86", "Suspicious login path"],
        recommendation="Do not submit credentials; verify using a trusted channel.",
    )
    alerts = database.get_security_alerts(
        search_query="credential-check",
        severity="Critical",
        analysis_type="phishing",
        status="OPEN",
    )
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["analysis_id"] == analysis_id
    assert alert["risk_score"] == 86
    assert alert["evidence"] == ["Phishing-class model output: 0.86", "Suspicious login path"]
    assert alert["created_at"].endswith("UTC")

    duplicate_id = database.create_security_alert(
        analysis_id,
        86,
        evidence=["duplicate invocation"],
        recommendation="duplicate",
    )
    assert duplicate_id == alert["id"]
    assert len(database.get_security_alerts()) == 1


def test_low_risk_stays_in_history_without_creating_alert(isolated_alert_database: None) -> None:
    analysis_id = database.save_analysis(
        analysis_type="network",
        input_summary="Batch: quiet.csv (20 records)",
        predicted_class="BENIGN",
        risk_level="Low",
        probability=0.02,
        model_name="Test model",
        result_summary="No attacks predicted.",
        risk_score=10,
        risk_evidence=["0 of 20 predicted attacks"],
        recommendation="Continue routine monitoring.",
    )
    assert database.get_analysis_history(limit=10)[0]["id"] == analysis_id
    assert database.get_security_alerts() == []
    assert database.create_security_alert(analysis_id, 10) is None


def test_alert_status_transitions_and_timestamps(isolated_alert_database: None) -> None:
    analysis_id = database.save_analysis(
        analysis_type="network",
        input_summary="Batch: suspicious.csv (3 records)",
        predicted_class="ATTACK",
        risk_level="High",
        probability=0.9,
        model_name="Test model",
        result_summary="Attack predictions found.",
        risk_score=90,
        risk_evidence=["3 of 3 flows predicted attack"],
        recommendation="Investigate and correlate before containment.",
    )
    alert_id = database.get_security_alerts()[0]["id"]
    assert database.update_security_alert_status(alert_id, "ACKNOWLEDGED") is True
    assert database.update_security_alert_status(alert_id, "ACKNOWLEDGED") is True
    acknowledged = database.get_security_alerts(status="ACKNOWLEDGED")[0]
    assert acknowledged["acknowledged_at"]

    assert database.update_security_alert_status(alert_id, "RESOLVED") is True
    resolved = database.get_security_alerts(status="RESOLVED")[0]
    assert resolved["resolved_at"]
    assert database.update_security_alert_status(alert_id, "ACKNOWLEDGED") is False
    assert database.update_security_alert_status(-1, "RESOLVED") is False
    with pytest.raises(ValueError):
        database.update_security_alert_status(alert_id, "OPEN")
