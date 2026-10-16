from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from ucimlrepo import fetch_ucirepo

from src.config import PHISHING_DATA_DIR, PHISHING_MODEL_DIR
from src.database import save_model_run
from src.risk_scoring import assess_phishing_risk
from src.url_features import (
    UCI_FEATURE_NAMES,
    extract_uci_compatible_features,
    get_feature_descriptions,
    validate_and_format_url,
)

TARGET_COLUMN = "result"
CATEGORY_MAP = {-1: "phishing", 1: "legitimate"}


def get_model_paths() -> dict[str, Path]:
    return {
        "model": PHISHING_MODEL_DIR / "best_model.joblib",
        "features": PHISHING_MODEL_DIR / "feature_names.json",
        "mapping": PHISHING_MODEL_DIR / "class_mapping.json",
        "metadata": PHISHING_MODEL_DIR / "metadata.json",
    }


def is_model_trained() -> bool:
    paths = get_model_paths()
    return paths["model"].exists() and paths["metadata"].exists()


def get_phishing_metadata() -> Optional[dict[str, Any]]:
    paths = get_model_paths()
    if not paths["metadata"].exists():
        return None
    try:
        with open(paths["metadata"], "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def load_phishing_model():
    paths = get_model_paths()
    if not paths["model"].exists() or not paths["features"].exists():
        raise FileNotFoundError(
            "Phishing model artifacts not found. Please train the model first by running scripts/train_phishing_model.py."
        )
    model = joblib.load(paths["model"])
    with open(paths["features"], "r", encoding="utf-8") as f:
        feature_names = json.load(f)
    return model, feature_names


def fetch_or_load_dataset() -> pd.DataFrame:
    """Fetch UCI Phishing Websites dataset or load from local cache."""
    cache_file = PHISHING_DATA_DIR / "uci_phishing_cached.csv"
    if cache_file.exists():
        return pd.read_csv(cache_file)

    try:
        dataset = fetch_ucirepo(id=327)
        features = dataset.data.features.copy()
        targets = dataset.data.targets.copy()
        if isinstance(targets, pd.DataFrame):
            targets = targets.iloc[:, 0]

        features.columns = [str(col).strip() for col in features.columns]
        targets = pd.Series(targets.reset_index(drop=True), name=TARGET_COLUMN)
        full_df = pd.concat([features.reset_index(drop=True), targets], axis=1)

        # Cache locally
        full_df.to_csv(cache_file, index=False)
        return full_df
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch UCI Phishing dataset (ID 327): {exc}. "
            "Ensure internet connectivity or place 'uci_phishing_cached.csv' in data/phishing/."
        ) from exc


def train_phishing_pipeline() -> dict[str, Any]:
    """
    Train and compare multiple classifiers on UCI Phishing dataset.
    Saves the best model and logs metrics to SQLite database.
    """
    df = fetch_or_load_dataset()
    feature_cols = [c for c in df.columns if c != TARGET_COLUMN]
    X = df[feature_cols].copy()
    y = df[TARGET_COLUMN].copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    candidate_models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=1000, random_state=42)),
        ]),
        "Decision Tree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=16, random_state=42, min_samples_leaf=2, class_weight="balanced"
        ),
    }

    comparison_results: dict[str, Any] = {}
    best_name = ""
    best_f1 = -1.0
    best_model_obj = None

    for name, clf in candidate_models.items():
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)

        acc = float(accuracy_score(y_test, preds))
        prec = float(precision_score(y_test, preds, pos_label=-1, zero_division=0))
        rec = float(recall_score(y_test, preds, pos_label=-1, zero_division=0))
        f1 = float(f1_score(y_test, preds, pos_label=-1, zero_division=0))
        cm = confusion_matrix(y_test, preds, labels=[-1, 1]).tolist()
        report = classification_report(y_test, preds, target_names=["Phishing (-1)", "Legitimate (+1)"], output_dict=True)

        comparison_results[name] = {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "confusion_matrix": cm,
            "classification_report": report,
        }

        # Save record to database
        save_model_run(
            model_type="phishing",
            model_name=name,
            dataset_name="UCI Phishing Websites (#327)",
            accuracy=acc,
            precision=prec,
            recall=rec,
            f1_score=f1,
            metadata={
                "train_size": len(X_train),
                "test_size": len(X_test),
                "confusion_matrix": cm,
            },
        )

        if f1 > best_f1:
            best_f1 = f1
            best_name = name
            best_model_obj = clf

    # Persist best model
    paths = get_model_paths()
    joblib.dump(best_model_obj, paths["model"])
    with open(paths["features"], "w", encoding="utf-8") as f:
        json.dump(feature_cols, f, indent=2)
    with open(paths["mapping"], "w", encoding="utf-8") as f:
        json.dump({str(k): v for k, v in CATEGORY_MAP.items()}, f, indent=2)

    meta = {
        "selected_model": best_name,
        "feature_columns": feature_cols,
        "target_column": TARGET_COLUMN,
        "class_mapping": {str(k): v for k, v in CATEGORY_MAP.items()},
        "metrics": comparison_results[best_name],
        "all_models": comparison_results,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "class_distribution": {
            "phishing": int((y == -1).sum()),
            "legitimate": int((y == 1).sum()),
        },
    }
    with open(paths["metadata"], "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return meta


def predict_url(raw_url: str) -> dict[str, Any]:
    """
    Classify a raw URL using passive lexical feature extraction and the trained model.
    """
    model, feature_names = load_phishing_model()
    validated_url = validate_and_format_url(raw_url)
    features, diagnostics = extract_uci_compatible_features(validated_url)

    # Order features according to training schema
    feature_df = pd.DataFrame([[features[col] for col in feature_names]], columns=feature_names)

    prediction_val = int(model.predict(feature_df)[0])
    predicted_label = CATEGORY_MAP.get(prediction_val, "unknown")

    # Probabilities
    probability = 0.5
    prob_map = {}
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(feature_df)[0]
        classes = model.classes_
        for cls_val, prob in zip(classes, probs):
            label_name = CATEGORY_MAP.get(int(cls_val), str(cls_val))
            prob_map[label_name] = float(prob)
        probability = prob_map.get(predicted_label, float(np.max(probs)))

    risk_assessment = assess_phishing_risk(
        predicted_label,
        prob_map.get("phishing"),
    )

    # Determine risk level
    if predicted_label == "phishing":
        risk_level = "High" if probability >= 0.70 else "Medium"
    else:
        risk_level = "Low" if probability >= 0.75 else "Medium"

    # Human-readable explanations
    explanation_points = []
    if features.get("having_ip_address") == -1:
        explanation_points.append("The URL uses an IP address instead of a standard registered domain name.")
    if features.get("shortining_service") == -1:
        explanation_points.append("A known URL shortener service is concealing the true destination.")
    if features.get("having_at_symbol") == -1:
        explanation_points.append("The '@' symbol is present, which causes browsers to disregard preceding characters.")
    if features.get("double_slash_redirecting") == -1:
        explanation_points.append("A double-slash redirection pattern ('//') is present after the URL scheme.")
    if features.get("prefix_suffix") == -1:
        explanation_points.append("A hyphen was detected in the domain name, which is frequently used to spoof legitimate brand identities.")
    if features.get("having_sub_domain") == -1:
        explanation_points.append("An unusually high number of subdomains is present, masking the target host.")
    if features.get("sslfinal_state") == -1:
        explanation_points.append("The link uses unencrypted HTTP rather than HTTPS.")
    if diagnostics.get("suspicious_keywords"):
        keywords_str = ", ".join(diagnostics["suspicious_keywords"])
        explanation_points.append(f"High-risk authentication/banking keywords were identified: [{keywords_str}].")

    if not explanation_points:
        explanation_points.append("The lexical structure conforms to typical legitimate internet naming patterns.")
    risk_assessment["risk_evidence"].extend(explanation_points)

    summary_text = (
        f"The URL was classified as {predicted_label.upper()} with {probability:.1%} confidence. "
        + " ".join(explanation_points)
    )

    return {
        "url": validated_url,
        "predicted_label": predicted_label,
        "prediction_value": prediction_val,
        "risk_level": risk_level,
        **risk_assessment,
        "confidence": probability,
        "probability_map": prob_map,
        "extracted_features": features,
        "diagnostics": diagnostics,
        "explanation_points": explanation_points,
        "summary": summary_text,
    }


def predict_engineered_features(feature_dict: dict[str, int]) -> dict[str, Any]:
    """
    Classify an explicitly provided 30-feature UCI vector.
    Enables academic validation and manual testing.
    """
    model, feature_names = load_phishing_model()
    missing = [c for c in feature_names if c not in feature_dict]
    if missing:
        raise ValueError(f"Missing required UCI features: {missing[:5]}...")

    feature_df = pd.DataFrame([[feature_dict[col] for col in feature_names]], columns=feature_names)
    pred_val = int(model.predict(feature_df)[0])
    pred_label = CATEGORY_MAP.get(pred_val, "unknown")

    prob = 0.5
    prob_map = {}
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(feature_df)[0]
        for cls_val, p in zip(model.classes_, probs):
            lbl = CATEGORY_MAP.get(int(cls_val), str(cls_val))
            prob_map[lbl] = float(p)
        prob = prob_map.get(pred_label, float(np.max(probs)))

    risk_assessment = assess_phishing_risk(pred_label, prob_map.get("phishing"))

    risk_level = "High" if pred_label == "phishing" else "Low"

    return {
        "predicted_label": pred_label,
        "prediction_value": pred_val,
        "risk_level": risk_level,
        **risk_assessment,
        "confidence": prob,
        "probability_map": prob_map,
        "features": feature_dict,
    }


# Backward compatibility alias
predict_phishing_url = predict_url
