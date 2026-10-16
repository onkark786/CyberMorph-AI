# Unified Risk Score and Security Alerts

## Purpose and interpretation

CyberMorph AI reports a unified 0–100 risk index to help order analyst review. It is derived from the model's actual class predictions and, when available, its `predict_proba` outputs. It is **not a calibrated probability**, a measure of certainty, or a guarantee that an input is safe or malicious. The existing model outputs and original `Risk_Level` fields remain available alongside the unified score.

## Scoring logic

### Phishing URL

When the trained model exposes class probabilities, the index is the phishing-class output multiplied by 100 and rounded to the nearest integer (half up):

`risk score = round_half_up(100 × model_output_for_phishing_class)`

The class is looked up by its semantic mapping (`-1` to phishing), not by assuming a fixed probability-column position. If a model has no probability output, the scoring helper falls back to the classifier's actual hard class (100 for phishing, 0 for legitimate) and records that the probability output was unavailable. This fallback is intentionally coarse.

### Network flow batch

For a model that exposes class probabilities, the index combines the share of flows predicted as attacks with the mean model output for the ATTACK class:

`risk score = round_half_up(100 × (0.70 × predicted_attack_share + 0.30 × mean_attack_class_output))`

The ATTACK probability column is located using the fitted model's class labels. If probability output is unavailable, the score uses the predicted attack share only; no probability is fabricated. Per-flow scores use that flow's ATTACK class output when available, or the hard predicted class (100/0) otherwise.

## Severity bands and configuration

Defaults are inclusive: Low 0–24, Medium 25–49, High 50–74, Critical 75–100. The upper bounds are configurable with environment variables `CYBERMORPH_RISK_LOW_MAX`, `CYBERMORPH_RISK_MEDIUM_MAX`, and `CYBERMORPH_RISK_HIGH_MAX`; they must be integers satisfying `0 <= low < medium < high < 100`. The Python `RiskBands` object can also be supplied explicitly by callers.

New history entries create a Security Alert Center record when their score is Medium, High, or Critical. Low-scored analyses remain in the existing analysis history, but do not create alerts. Alert rows snapshot score, severity, evidence, recommendation, target, prediction, timestamps, and status. A unique constraint on `analysis_id` makes alert creation idempotent. Status flow is Open → Acknowledged → Resolved; resolving an open alert is also allowed.

## Evidence and operational caveats

Phishing alert evidence contains the model's phishing-class output and lexical explanation points returned by the current prediction pipeline. Network alert evidence contains actual predicted attack counts and the actual mean ATTACK-class output when available. Recommendations request validation/correlation and do not automatically block hosts or traffic. The app performs batch analysis only; it does not monitor a live network.
