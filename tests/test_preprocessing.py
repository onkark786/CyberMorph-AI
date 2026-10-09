from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
import pytest
from src.preprocessing import (
    clean_column_names,
    normalize_network_labels,
    sanitize_numeric_features,
    validate_input_schema,
)


def test_clean_column_names():
    """Verify whitespace stripping and normalization in column headers."""
    df = pd.DataFrame({" Destination Port ": [80], "Flow  Duration": [1000]})
    cleaned = clean_column_names(df)
    assert "Destination Port" in cleaned.columns
    assert "Flow Duration" in cleaned.columns


def test_sanitize_numeric_features_handles_inf_and_nan():
    """Verify infinite and NaN values are correctly replaced and imputed."""
    df = pd.DataFrame({
        "feature_a": [1.0, np.inf, 3.0, np.nan],
        "feature_b": [-np.inf, 2.0, 4.0, 6.0],
    })
    sanitized = sanitize_numeric_features(df, ["feature_a", "feature_b"])

    # No inf or nan remaining
    assert not np.isinf(sanitized["feature_a"]).any()
    assert not np.isnan(sanitized["feature_a"]).any()
    assert not np.isinf(sanitized["feature_b"]).any()
    assert not np.isnan(sanitized["feature_b"]).any()


def test_normalize_network_labels():
    """Verify CIC-IDS2017 labels are mapped to binary Benign (0) and Attack (1)."""
    labels = pd.Series(["BENIGN", "PortScan", "DDoS", " benign ", "Bot"])
    y, id_map, _ = normalize_network_labels(labels, binary_mode=True)

    assert y.iloc[0] == 0
    assert y.iloc[1] == 1
    assert y.iloc[2] == 1
    assert y.iloc[3] == 0
    assert y.iloc[4] == 1


def test_validate_input_schema():
    """Verify missing required columns are properly identified."""
    df = pd.DataFrame({"col_a": [1], "col_b": [2]})
    is_valid, missing = validate_input_schema(df, ["col_a", "col_b"])
    assert is_valid is True
    assert len(missing) == 0

    is_valid_fail, missing_fail = validate_input_schema(df, ["col_a", "col_c", "col_d"])
    assert is_valid_fail is False
    assert "col_c" in missing_fail
    assert "col_d" in missing_fail
