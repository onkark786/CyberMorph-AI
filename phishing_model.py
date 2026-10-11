from __future__ import annotations

import json
import math
import re
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from joblib import dump, load
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from ucimlrepo import fetch_ucirepo

PROJECT_ROOT = Path(__file__).resolve().parent
MODEL_DIR = PROJECT_ROOT / "models" / "phishing"
DATA_DIR = PROJECT_ROOT / "data" / "phishing"

FEATURE_COLUMNS = [
    "having_ip_address",
    "url_length",
    "shortining_service",
    "having_at_symbol",
    "double_slash_redirecting",
    "prefix_suffix",
    "having_sub_domain",
    "sslfinal_state",
    "domain_registration_length",
    "favicon",
    "port",
    "https_token",
    "request_url",
    "url_of_anchor",
    "links_in_tags",
    "sfh",
    "submitting_to_email",
    "abnormal_url",
    "redirect",
    "on_mouseover",
    "rightclick",
    "popupwindow",
    "iframe",
    "age_of_domain",
    "dnsrecord",
    "web_traffic",
    "page_rank",
    "google_index",
    "links_pointing_to_page",
    "statistical_report",
    "result",
]

TARGET_COLUMN = "result"
CATEGORY_MAP = {
    -1: "phishing",
    1: "legitimate",
}


def ensure_dirs() -> None:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def fetch_phishing_dataset() -> pd.DataFrame:
    ensure_dirs()
    try:
        dataset = fetch_ucirepo(id=327)
    except Exception as exc:  # pragma: no cover - defensive error path
        raise RuntimeError(
            "The UCI phishing dataset could not be loaded automatically. "
            "Check your internet connection and the ucimlrepo package."
        ) from exc

    features = dataset.data.features.copy()
    targets = dataset.data.targets.copy()
    if isinstance(targets, pd.DataFrame):
        targets = targets.iloc[:, 0]
    features.columns = [str(col).strip() for col in features.columns]
    features = features.reset_index(drop=True)
    targets = pd.Series(targets.reset_index(drop=True), name=TARGET_COLUMN)
    data = pd.concat([features, targets], axis=1)
    return data


def _parse_url(url: str) -> tuple[str, str, str, list[str]]:
    value = (url or "").strip()
    if not value:
        raise ValueError("Please enter a valid URL before analyzing.")
    if not re.match(r"^https?://", value, flags=re.IGNORECASE):
        value = "https://" + value
    parsed = urlparse(value)
    host = parsed.netloc.lower()
    domain = host.split(":")[0]
    path = parsed.path.lower()
    return value, host, domain, (host, domain, path)


def extract_url_features(url: str) -> dict[str, int]:
    value, host, domain, _ = _parse_url(url)
    lower_url = value.lower()
    hostname = host.lower()

    def safe_int(value: int | bool) -> int:
        return int(1 if value else -1)

    features = {
        "having_ip_address": safe_int(re.search(r"\d+\.\d+\.\d+\.\d+", hostname) is not None),
        "url_length": safe_int(len(value) > 54),
        "shortining_service": safe_int(any(token in lower_url for token in ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"])),
        "having_at_symbol": safe_int("@" in lower_url),
        "double_slash_redirecting": safe_int(lower_url.rfind("//") > 7),
        "prefix_suffix": safe_int("-" in domain),
        "having_sub_domain": safe_int(domain.count(".") >= 2),
        "sslfinal_state": safe_int(lower_url.startswith("https://") and ":443" not in host),
        "domain_registration_length": safe_int(len(domain) > 15),
        "favicon": -1,
        "port": -1,
        "https_token": safe_int("https://" in lower_url and "https_token" in lower_url),
        "request_url": -1,
        "url_of_anchor": -1,
        "links_in_tags": -1,
        "sfh": -1,
        "submitting_to_email": -1,
        "abnormal_url": -1,
        "redirect": safe_int(lower_url.count("//") > 1),
        "on_mouseover": -1,
        "rightclick": -1,
        "popupwindow": -1,
        "iframe": -1,
        "age_of_domain": safe_int(len(domain) > 10),
        "dnsrecord": -1,
        "web_traffic": -1,
        "page_rank": -1,
        "google_index": 1,
        "links_pointing_to_page": -1,
        "statistical_report": -1,
    }

    if "login" in lower_url or "account" in lower_url:
        features["submitting_to_email"] = 1
    if "http://" in lower_url and lower_url.startswith("http://"):
        features["sslfinal_state"] = -1
    if "//" in lower_url and lower_url.index("//") > 7:
        features["double_slash_redirecting"] = 1
    if domain.startswith("www."):
        features["having_sub_domain"] = 1 if domain.count(".") > 2 else -1
    if domain.count(".") > 2:
        features["having_sub_domain"] = 1
    if any(t in lower_url for t in ["signin", "login", "verify", "update", "security", "banking"]):
        features["page_rank"] = -1
    if any(t in lower_url for t in ["bank", "paypal", "login", "secure", "account"]):
        features["web_traffic"] = 1

    return features


def normalize_feature_vector(raw_features: dict[str, int]) -> pd.DataFrame:
    feature_names = [col for col in FEATURE_COLUMNS if col != TARGET_COLUMN]
    missing = [col for col in feature_names if col not in raw_features]
    if missing:
        raise ValueError(f"Missing feature values for: {missing}")

    ordered = {col: int(raw_features[col]) for col in feature_names}
    return pd.DataFrame([ordered], columns=feature_names)


def build_training_data() -> tuple[pd.DataFrame, pd.Series]:
    data = fetch_phishing_dataset()
    feature_columns = [col for col in data.columns if col != TARGET_COLUMN]
    X = data[feature_columns].copy()
    y = data[TARGET_COLUMN].copy()
    y = pd.Series(y, name=TARGET_COLUMN)
    return X, y


def get_model_bundle() -> tuple[dict[str, Pipeline], dict[str, dict[str, float]], dict[str, list[str]]]:
    X, y = build_training_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model_specs = {
        "decision_tree": DecisionTreeClassifier(random_state=42, max_depth=8),
        "logistic_regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=2000, random_state=42)),
        ]),
        "random_forest": RandomForestClassifier(
            n_estimators=300,
            random_state=42,
            min_samples_leaf=2,
            max_depth=None,
            class_weight="balanced",
        ),
    }

    results: dict[str, dict[str, float]] = {}
    trained: dict[str, Pipeline] = {}

    for name, model in model_specs.items():
        model.fit(X_train, y_train)
        predictions = model.predict(X_test)
        results[name] = {
            "accuracy": float(accuracy_score(y_test, predictions)),
            "precision": float(precision_score(y_test, predictions, zero_division=0)),
            "recall": float(recall_score(y_test, predictions, zero_division=0)),
            "f1": float(f1_score(y_test, predictions, zero_division=0)),
            "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        }
        trained[name] = model

    return trained, results, X.columns.tolist()


def save_model_bundle(selected_model_name: str, model, feature_columns: list[str], result_metrics: dict[str, float]) -> None:
    ensure_dirs()
    dump(model, MODEL_DIR / "best_model.joblib")
    with (MODEL_DIR / "feature_names.json").open("w", encoding="utf-8") as handle:
        json.dump(feature_columns, handle, ensure_ascii=False, indent=2)

    class_mapping = {str(k): v for k, v in CATEGORY_MAP.items()}
    with (MODEL_DIR / "class_mapping.json").open("w", encoding="utf-8") as handle:
        json.dump(class_mapping, handle, ensure_ascii=False, indent=2)

    metadata = {
        "selected_model": selected_model_name,
        "feature_columns": feature_columns,
        "target_column": TARGET_COLUMN,
        "class_mapping": {str(k): v for k, v in CATEGORY_MAP.items()},
        "metrics": result_metrics,
    }
    with (MODEL_DIR / "metadata.json").open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, ensure_ascii=False, indent=2)


def train_and_save_phishing_model() -> dict[str, dict[str, float]]:
    trained_models, results, feature_columns = get_model_bundle()
    selected_model_name = max(results, key=lambda key: results[key]["f1"])
    save_model_bundle(selected_model_name, trained_models[selected_model_name], feature_columns, results[selected_model_name])
    return results


def load_saved_model():
    model_path = MODEL_DIR / "best_model.joblib"
    feature_path = MODEL_DIR / "feature_names.json"
    if not model_path.exists() or not feature_path.exists():
        raise FileNotFoundError(
            "The trained phishing model is missing. Run: python train_phishing_model.py"
        )
    model = load(model_path)
    with feature_path.open("r", encoding="utf-8") as handle:
        feature_columns = json.load(handle)
    return model, feature_columns


def predict_phishing_url(url: str):
    model, feature_columns = load_saved_model()
    raw_features = extract_url_features(url)
    feature_vector = normalize_feature_vector(raw_features)
    feature_vector = feature_vector[feature_columns]
    prediction = model.predict(feature_vector)[0]
    probabilities = model.predict_proba(feature_vector)[0] if hasattr(model, "predict_proba") else None
    class_name = CATEGORY_MAP.get(int(prediction), "unknown")
    risk_level = "high" if class_name == "phishing" else "low"
    probability = float(np.max(probabilities)) if probabilities is not None else 0.0
    probability_map = {
        label: float(prob)
        for label, prob in zip(model.classes_, probabilities if probabilities is not None else [1.0, 0.0])
    }
    return {
        "prediction": class_name,
        "risk_level": risk_level,
        "confidence": round(probability, 4),
        "probability_map": probability_map,
        "class_value": int(prediction),
        "feature_vector": feature_vector.iloc[0].to_dict(),
        "features": raw_features,
    }


def explain_prediction(url: str, prediction: str, feature_vector: dict[str, int]) -> str:
    heuristics = []
    if feature_vector.get("having_ip_address", -1) == 1:
        heuristics.append("The URL includes an IP address instead of a normal domain name.")
    if feature_vector.get("shortining_service", -1) == 1:
        heuristics.append("A URL shortener is being used, which is common in phishing campaigns.")
    if feature_vector.get("having_at_symbol", -1) == 1:
        heuristics.append("The URL contains an @ symbol, which can hide the real destination.")
    if feature_vector.get("double_slash_redirecting", -1) == 1:
        heuristics.append("The URL contains a redirect pattern that may be used to hide the destination.")
    if feature_vector.get("prefix_suffix", -1) == 1:
        heuristics.append("The domain includes suspicious prefix or suffix formatting.")
    if feature_vector.get("sslfinal_state", -1) == -1:
        heuristics.append("The URL does not show a strong HTTPS/SSL signal.")

    if not heuristics:
        heuristics.append("No strong phishing indicators were detected from the extracted URL feature set.")

    if prediction == "phishing":
        explanation = "This URL was classified as phishing by the trained model. " + " ".join(heuristics)
    else:
        explanation = "This URL was classified as legitimate by the trained model. " + " ".join(heuristics)
    return explanation
