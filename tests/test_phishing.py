from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from src.phishing import (
    is_model_trained,
    load_phishing_model,
    predict_engineered_features,
    predict_url,
)
from src.url_features import UCI_FEATURE_NAMES


def test_phishing_model_artifacts_exist():
    """Verify phishing model artifacts are present and loadable."""
    assert is_model_trained() is True
    model, feature_names = load_phishing_model()
    assert model is not None
    assert len(feature_names) == 30


def test_predict_url():
    """Verify live URL inference runs and outputs required schema."""
    result = predict_url("https://www.wikipedia.org")
    assert "predicted_label" in result
    assert result["predicted_label"] in ("phishing", "legitimate")
    assert "risk_level" in result
    assert result["risk_level"] in ("Low", "Medium", "High")
    assert "confidence" in result
    assert 0.0 <= result["confidence"] <= 1.0
    assert "explanation_points" in result
    assert len(result["explanation_points"]) > 0


def test_predict_engineered_features():
    """Verify direct evaluation of engineered feature vectors."""
    # Vector representing safe, legitimate site
    safe_vector = {feat: 1 for feat in UCI_FEATURE_NAMES}
    res_safe = predict_engineered_features(safe_vector)
    assert res_safe["predicted_label"] in ("phishing", "legitimate")
    assert res_safe["confidence"] >= 0.0

    # Vector representing extreme phishing signals
    phish_vector = {feat: -1 for feat in UCI_FEATURE_NAMES}
    res_phish = predict_engineered_features(phish_vector)
    assert res_phish["predicted_label"] == "phishing"
    assert res_phish["risk_level"] == "High"
