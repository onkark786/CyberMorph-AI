from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from src.url_features import (
    UCI_FEATURE_NAMES,
    extract_uci_compatible_features,
    sanitize_url_for_storage,
    validate_and_format_url,
)


def test_validate_and_format_url_valid():
    """Verify standard URLs format correctly."""
    url = validate_and_format_url("https://www.google.com")
    assert url == "https://www.google.com"


def test_validate_and_format_url_missing_scheme():
    """Verify URLs without scheme default to https://."""
    url = validate_and_format_url("example.com/test")
    assert url.startswith("https://")


def test_validate_and_format_url_rejects_unsafe():
    """Verify unsafe protocols are rejected."""
    with pytest.raises(ValueError):
        validate_and_format_url("javascript:alert(1)")

    with pytest.raises(ValueError):
        validate_and_format_url("file:///etc/passwd")

    with pytest.raises(ValueError):
        validate_and_format_url("")


def test_extract_uci_features_shape():
    """Verify extraction yields exactly the 30 UCI features with valid ternary values."""
    features, diagnostics = extract_uci_compatible_features("https://github.com")
    assert len(features) == 30
    assert set(features.keys()) == set(UCI_FEATURE_NAMES)

    # Check values are in {-1, 0, 1}
    for k, v in features.items():
        assert v in (-1, 0, 1), f"Feature {k} has unexpected value {v}"


def test_extract_uci_features_phishing_signatures():
    """Verify phishing heuristics are correctly triggered."""
    phish_url = "http://192.168.1.1/login.php?redirect=http://paypal.com@attacker.com"
    features, diagnostics = extract_uci_compatible_features(phish_url)

    # IP address detected
    assert features["having_ip_address"] == -1
    # HTTP protocol
    assert features["sslfinal_state"] == -1
    # @ symbol detected
    assert features["having_at_symbol"] == -1
    # Diagnostics flag
    assert diagnostics["has_ip"] is True
    assert diagnostics["has_at_symbol"] is True


def test_sanitize_url_for_storage():
    """Verify URLs are sanitized for privacy."""
    sanitized = sanitize_url_for_storage("https://user:pass@bank.com/account?token=secret123")
    assert "secret123" not in sanitized
    assert "pass" not in sanitized
    assert "bank.com" in sanitized
