from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Any, Optional, Sequence


@dataclass(frozen=True)
class RiskBands:
    """Configurable inclusive upper bounds for Low, Medium, and High scores."""

    low_max: int = 24
    medium_max: int = 49
    high_max: int = 74

    def __post_init__(self) -> None:
        if not (0 <= self.low_max < self.medium_max < self.high_max < 100):
            raise ValueError("Risk band bounds must satisfy 0 <= low < medium < high < 100.")

    def classify(self, score: int) -> str:
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            raise ValueError("Risk score must be an integer from 0 to 100.")
        if score <= self.low_max:
            return "Low"
        if score <= self.medium_max:
            return "Medium"
        if score <= self.high_max:
            return "High"
        return "Critical"


DEFAULT_RISK_BANDS = RiskBands(
    low_max=int(os.getenv("CYBERMORPH_RISK_LOW_MAX", "24")),
    medium_max=int(os.getenv("CYBERMORPH_RISK_MEDIUM_MAX", "49")),
    high_max=int(os.getenv("CYBERMORPH_RISK_HIGH_MAX", "74")),
)


def _validated_probability(value: Any, name: str) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a finite number from 0 to 1.")
    try:
        probability = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite number from 0 to 1.") from exc
    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise ValueError(f"{name} must be a finite number from 0 to 1.")
    return probability


def _result(score: int, evidence: list[str], recommendation: str, bands: RiskBands) -> dict[str, Any]:
    bounded_score = max(0, min(100, int(math.floor(score + 0.5))))
    return {
        "risk_score": bounded_score,
        "risk_severity": bands.classify(bounded_score),
        "risk_evidence": evidence,
        "recommendation": recommendation,
        "score_kind": "model-derived risk index; not a calibrated probability",
    }


def assess_phishing_risk(
    predicted_label: str,
    phishing_probability: Any = None,
    *,
    bands: RiskBands = DEFAULT_RISK_BANDS,
) -> dict[str, Any]:
    """Score a URL from the phishing class output, without treating it as calibrated."""
    label = str(predicted_label or "").strip().lower()
    probability = _validated_probability(phishing_probability, "phishing_probability")
    if probability is None:
        if label not in {"phishing", "legitimate"}:
            raise ValueError("A supported prediction or phishing-class output is required.")
        score = 100 if label == "phishing" else 0
        evidence = [f"Model class prediction: {label}; probability output was unavailable."]
    else:
        score = 100 * probability
        evidence = [f"Model phishing-class output: {probability:.4f} (used as an uncalibrated risk-index input)."]
        if label in {"phishing", "legitimate"}:
            evidence.append(f"Model class prediction: {label}.")

    if label == "phishing":
        recommendation = "Do not open the URL or submit credentials; verify the domain through a trusted channel and report/block it under local policy."
    else:
        recommendation = "Treat this classification as a lexical-model signal only; verify the destination independently before entering sensitive information."
    return _result(score, evidence, recommendation, bands)


def assess_network_risk(
    predicted_labels: Sequence[Any],
    attack_probabilities: Optional[Sequence[Any]] = None,
    *,
    bands: RiskBands = DEFAULT_RISK_BANDS,
) -> dict[str, Any]:
    """Score a flow batch from real model predictions and optional class probabilities.

    When probabilities exist, the index is 70% predicted-attack share and 30%
    mean model attack-class output. Without probability outputs, the score is
    the predicted-attack share only; no probability is fabricated.
    """
    labels = [str(label).strip().upper() for label in predicted_labels]
    if not labels:
        raise ValueError("At least one network prediction is required to score risk.")
    invalid = [label for label in labels if label not in {"ATTACK", "BENIGN", "1", "0"}]
    if invalid:
        raise ValueError(f"Unsupported network prediction label: {invalid[0]!r}.")

    attack_count = sum(label in {"ATTACK", "1"} for label in labels)
    attack_share = attack_count / len(labels)
    evidence = [f"{attack_count} of {len(labels)} flows were predicted as attack ({attack_share:.1%})."]

    if attack_probabilities is None:
        score = 100 * attack_share
        evidence.append("No attack-class probabilities were available; score uses predicted-attack share only.")
    else:
        if len(attack_probabilities) != len(labels):
            raise ValueError("The attack probability count must match the prediction count.")
        probabilities = [
            _validated_probability(value, "attack_probability")
            for value in attack_probabilities
        ]
        if any(value is None for value in probabilities):
            raise ValueError("Attack probabilities must not contain missing values.")
        mean_probability = sum(value for value in probabilities if value is not None) / len(probabilities)
        score = 100 * (0.70 * attack_share + 0.30 * mean_probability)
        evidence.append(
            f"Mean model attack-class output: {mean_probability:.4f}; batch formula = 70% predicted-attack share + 30% mean output."
        )

    if attack_count:
        recommendation = "Review flagged flows and correlate them with endpoint, firewall, and threat-intelligence telemetry before taking containment action."
    else:
        recommendation = "No flow was classified as an attack in this batch; retain the result and correlate with independent monitoring."
    return _result(score, evidence, recommendation, bands)
