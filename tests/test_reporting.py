from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import pytest
from src.reporting import generate_csv_bytes, generate_security_pdf_report


def test_generate_csv_bytes():
    """Verify DataFrame converts to valid UTF-8 CSV bytes."""
    df = pd.DataFrame({"col_a": [1, 2], "col_b": ["apple", "banana"]})
    csv_bytes = generate_csv_bytes(df)
    assert isinstance(csv_bytes, bytes)
    assert b"col_a,col_b" in csv_bytes
    assert b"apple" in csv_bytes


def test_generate_security_pdf_report():
    """Verify PDF generator produces valid binary PDF data."""
    mock_stats = {
        "total_analyses": 10,
        "total_phishing": 5,
        "malicious_phishing": 2,
        "legitimate_phishing": 3,
        "total_network_flows": 100,
        "attack_network_flows": 15,
        "benign_network_flows": 85,
        "high_risk_count": 3,
    }
    mock_phish_meta = {
        "selected_model": "Random Forest",
        "metrics": {"accuracy": 0.965, "precision": 0.96, "recall": 0.97, "f1_score": 0.965},
    }
    mock_net_meta = {
        "selected_model": "Logistic Regression",
        "metrics": {"accuracy": 0.99, "precision": 0.98, "recall": 1.0, "f1_score": 0.99},
    }
    mock_records = [
        {
            "id": 1,
            "timestamp": "2026-10-09 12:00:00 UTC",
            "analysis_type": "phishing",
            "input_summary": "https://paypal-verify.com",
            "predicted_class": "PHISHING",
            "risk_level": "High",
        }
    ]

    pdf_bytes = generate_security_pdf_report(
        overview_stats=mock_stats,
        phishing_meta=mock_phish_meta,
        network_meta=mock_net_meta,
        recent_records=mock_records,
    )

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    # Valid PDF files start with %PDF
    assert pdf_bytes.startswith(b"%PDF")
