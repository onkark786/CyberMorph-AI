import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import PHISHING_MODEL_DIR
from src.phishing import predict_url


def test_model_feature_schema_matches_prediction_inputs():
    feature_file = PHISHING_MODEL_DIR / "feature_names.json"
    expected_features = json.loads(feature_file.read_text(encoding="utf-8"))
    result = predict_url("https://example.com")
    assert set(result["extracted_features"].keys()) == set(expected_features)
    assert result["predicted_label"] in {"phishing", "legitimate"}
