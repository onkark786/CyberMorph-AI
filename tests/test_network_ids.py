from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import pytest
from src.config import NETWORK_DATA_DIR
from src.network_ids import (
    analyze_network_traffic_df,
    is_network_model_trained,
    load_network_model,
    run_network_data_audit,
)


def test_network_model_artifacts_exist():
    """Verify network model artifacts are present and loadable."""
    assert is_network_model_trained() is True
    model, feature_names = load_network_model()
    assert model is not None
    assert len(feature_names) > 10


def test_analyze_sample_network_flows():
    """Verify running inference on sample test flows CSV."""
    sample_path = NETWORK_DATA_DIR / "sample_test_flows.csv"
    assert sample_path.exists(), "Sample test flows CSV must exist"

    sample_df = pd.read_csv(sample_path)
    enriched_df, summary = analyze_network_traffic_df(
        df=sample_df,
        source_name="Pytest Sample Test",
        persist_history=False,
    )

    assert "Predicted_Class" in enriched_df.columns
    assert "Attack_Probability" in enriched_df.columns
    assert "Risk_Level" in enriched_df.columns
    assert "Risk_Score" in enriched_df.columns
    assert "Risk_Severity" in enriched_df.columns
    assert 0 <= summary["risk_score"] <= 100
    assert summary["risk_severity"] in ("Low", "Medium", "High", "Critical")
    assert summary["risk_evidence"]
    assert summary["mean_attack_probability"] == pytest.approx(
        enriched_df["Attack_Probability"].mean(), abs=0.0001
    )

    assert summary["total_records"] == len(sample_df)
    assert summary["attack_records"] + summary["benign_records"] == len(sample_df)
    assert summary["overall_risk"] in ("Low", "Medium", "High")


def test_analyze_network_rejects_missing_schema():
    """Verify inference gracefully raises ValueError on malformed/missing schema."""
    bad_df = pd.DataFrame({"random_col_1": [1, 2], "random_col_2": [3, 4]})
    with pytest.raises(ValueError) as excinfo:
        analyze_network_traffic_df(bad_df, persist_history=False)
    assert "missing" in str(excinfo.value).lower()


def test_run_network_data_audit_flags_target_leakage_risk():
    """Verify the audit catches target-derived or duplicated features before training."""
    df = pd.DataFrame({
        "Label": ["BENIGN", "ATTACK", "BENIGN", "ATTACK"],
        "Feature_A": [10, 20, 10, 20],
        "Label_Encoded": [0, 1, 0, 1],
        "Feature_C": [1.0, 2.0, 1.0, 2.0],
    })

    audit = run_network_data_audit(df, "Label")
    assert audit["target_column_present"] is True
    assert audit["target_excluded_from_features"] is False
    assert any(col.lower() == "label_encoded" for col in audit["possible_target_derived_columns"])
    assert audit["duplicate_rows"] >= 0
