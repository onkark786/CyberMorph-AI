from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import pytest
from src.analysis_digs import (
    create_flow_scatter_dig,
    create_port_attack_distribution_dig,
    create_signal_waterfall_dig,
    create_threat_gauge,
    create_url_threat_radar,
)


def test_create_threat_gauge():
    """Verify threat gauge meter produces valid Plotly figure."""
    fig = create_threat_gauge(85.5, title="Test Gauge")
    assert fig is not None
    assert len(fig.data) > 0


def test_create_url_threat_radar():
    """Verify 5-pillar threat radar produces valid Plotly polar scatter."""
    mock_features = {
        "having_ip_address": -1,
        "having_sub_domain": -1,
        "sslfinal_state": -1,
        "url_length": -1,
        "shortining_service": -1,
        "having_at_symbol": -1,
        "double_slash_redirecting": -1,
        "prefix_suffix": -1,
        "https_token": 1,
    }
    fig = create_url_threat_radar(mock_features)
    assert fig is not None
    assert len(fig.data) > 0


def test_create_flow_scatter_dig():
    """Verify flow scatter dig produces valid 2D anomaly plot."""
    df = pd.DataFrame({
        "Flow Duration": [100, 200, 300, 400],
        "Flow Packets/s": [10.0, 50.0, 1000.0, 2000.0],
        "Predicted_Class": ["BENIGN", "BENIGN", "ATTACK", "ATTACK"],
    })
    fig = create_flow_scatter_dig(df)
    assert fig is not None
    assert len(fig.data) > 0


def test_create_port_attack_distribution_dig():
    """Verify destination port analysis dig."""
    df = pd.DataFrame({
        "Destination Port": [80, 443, 80, 22, 54321],
        "Predicted_Class": ["BENIGN", "BENIGN", "ATTACK", "BENIGN", "ATTACK"],
    })
    fig = create_port_attack_distribution_dig(df)
    assert fig is not None


def test_create_signal_waterfall_dig():
    """Verify signal waterfall dig produces valid Plotly bar figure."""
    df = pd.DataFrame({
        "Signal Name": ["IP Address", "URL Length", "SSL Protocol"],
        "Status": ["Suspicious", "Suspicious", "Normal"],
    })
    fig = create_signal_waterfall_dig(df)
    assert fig is not None
    assert len(fig.data) > 0
