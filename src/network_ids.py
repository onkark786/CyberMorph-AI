from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional, Union

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

from src.config import NETWORK_DATA_DIR, NETWORK_MODEL_DIR
from src.database import save_analysis, save_model_run
from src.preprocessing import (
    clean_column_names,
    normalize_network_labels,
    sanitize_numeric_features,
    validate_input_schema,
)
from src.risk_scoring import DEFAULT_RISK_BANDS, assess_network_risk

TARGET_LABEL_COL = "Label"
NETWORK_CLASSES = {0: "BENIGN", 1: "ATTACK"}


def run_network_data_audit(df: pd.DataFrame, target_col: str = TARGET_LABEL_COL) -> dict[str, Any]:
    """Audit the network dataset for obvious leakage, duplication, and target-derived features."""
    audit = {
        "target_column_present": target_col in df.columns,
        "target_excluded_from_features": False,
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_fraction": float(df.duplicated().mean()) if len(df) else 0.0,
        "missing_values": int(df.isna().sum().sum()),
        "possible_target_derived_columns": [],
        "warnings": [],
    }

    if not audit["target_column_present"]:
        audit["warnings"].append(f"Target column '{target_col}' was not found in the dataset.")
        return audit

    features = [c for c in df.columns if c != target_col]
    labelish = [c for c in features if "label" in c.lower() or "target" in c.lower()]
    audit["possible_target_derived_columns"] = labelish
    if labelish:
        audit["warnings"].append(
            "Target-derived columns were found in the feature set; these can cause label leakage."
        )

    if df.duplicated().sum() > 0:
        audit["warnings"].append(
            "Duplicate or near-duplicate records were found in the dataset; this can inflate metrics."
        )

    if target_col in df.columns and len(features) > 0:
        audit["target_excluded_from_features"] = target_col not in features and not labelish

    if len(df) > 0:
        y = df[target_col].astype(str)
        audit["class_distribution"] = {k: int((y == k).sum()) for k in sorted(y.unique())[:10]}
    else:
        audit["class_distribution"] = {}

    return audit


def get_network_model_paths() -> dict[str, Path]:
    return {
        "model": NETWORK_MODEL_DIR / "best_model.joblib",
        "features": NETWORK_MODEL_DIR / "feature_names.json",
        "mapping": NETWORK_MODEL_DIR / "class_mapping.json",
        "metadata": NETWORK_MODEL_DIR / "metadata.json",
    }


def is_network_model_trained() -> bool:
    paths = get_network_model_paths()
    return paths["model"].exists() and paths["metadata"].exists()


def get_network_metadata() -> Optional[dict[str, Any]]:
    paths = get_network_model_paths()
    if not paths["metadata"].exists():
        return None
    try:
        with open(paths["metadata"], "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def load_network_model():
    paths = get_network_model_paths()
    if not paths["model"].exists() or not paths["features"].exists():
        raise FileNotFoundError(
            "Network IDS model artifacts not found. Please train the model first by running scripts/train_network_model.py."
        )
    model = joblib.load(paths["model"])
    with open(paths["features"], "r", encoding="utf-8") as f:
        feature_names = json.load(f)
    return model, feature_names


def load_training_data() -> pd.DataFrame:
    """Find and load CIC-IDS2017 training CSV from data/network directory."""
    candidate_files = [
        NETWORK_DATA_DIR / "cicids2017_subset.csv",
        NETWORK_DATA_DIR / "cicids2017.csv",
        NETWORK_DATA_DIR / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        NETWORK_DATA_DIR / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        NETWORK_DATA_DIR / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    ]
    for p in candidate_files:
        if p.exists():
            return pd.read_csv(p)

    # Search for any CSV with Label column
    for csv_file in NETWORK_DATA_DIR.glob("*.csv"):
        sample = pd.read_csv(csv_file, nrows=5)
        clean_cols = [c.strip() for c in sample.columns]
        if "Label" in clean_cols or "label" in clean_cols:
            return pd.read_csv(csv_file)

    raise FileNotFoundError(
        f"No CIC-IDS2017 dataset found in {NETWORK_DATA_DIR}. "
        "Run 'python scripts/generate_sample_data.py' or place a CIC-IDS2017 CSV file in data/network/."
    )


def train_network_pipeline() -> dict[str, Any]:
    """
    Train and compare multiple models on CIC-IDS2017 network flow records.
    Saves best model and logs evaluation to SQLite.
    """
    df = load_training_data()
    df = clean_column_names(df)

    # Find target column
    label_col = next((c for c in df.columns if c.lower() == "label"), None)
    if not label_col:
        raise ValueError("Dataset does not contain a 'Label' column.")

    audit = run_network_data_audit(df, label_col)
    if audit["warnings"]:
        print("[Network Audit] Warning(s):")
        for warning in audit["warnings"]:
            print(f"  - {warning}")
    print(f"[Network Audit] Duplicate rows: {audit['duplicate_rows']} | Class distribution: {audit['class_distribution']}")

    raw_y = df[label_col].copy()
    y, id_to_label, _ = normalize_network_labels(raw_y, binary_mode=True)

    feature_cols = [c for c in df.columns if c != label_col]
    X_raw = df[feature_cols].copy()
    X = sanitize_numeric_features(X_raw, feature_columns=feature_cols)

    # Train/test split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=1000, random_state=42)),
        ]),
        "Decision Tree": DecisionTreeClassifier(max_depth=12, random_state=42),
        "Random Forest": RandomForestClassifier(
            n_estimators=150, max_depth=16, random_state=42, min_samples_leaf=2, class_weight="balanced"
        ),
    }

    comparison: dict[str, Any] = {}
    best_name = ""
    best_f1 = -1.0
    best_model_obj = None

    for name, clf in models.items():
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)

        acc = float(accuracy_score(y_test, preds))
        prec = float(precision_score(y_test, preds, pos_label=1, zero_division=0))
        rec = float(recall_score(y_test, preds, pos_label=1, zero_division=0))
        f1 = float(f1_score(y_test, preds, pos_label=1, zero_division=0))
        cm = confusion_matrix(y_test, preds, labels=[0, 1]).tolist()
        report = classification_report(y_test, preds, target_names=["Benign (0)", "Attack (1)"], output_dict=True)

        comparison[name] = {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "confusion_matrix": cm,
            "classification_report": report,
        }

        save_model_run(
            model_type="network",
            model_name=name,
            dataset_name="CIC-IDS2017 Flow Subset",
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

    # Save artifacts
    paths = get_network_model_paths()
    joblib.dump(best_model_obj, paths["model"])
    with open(paths["features"], "w", encoding="utf-8") as f:
        json.dump(feature_cols, f, indent=2)
    with open(paths["mapping"], "w", encoding="utf-8") as f:
        json.dump({str(k): v for k, v in NETWORK_CLASSES.items()}, f, indent=2)

    meta = {
        "selected_model": best_name,
        "feature_columns": feature_cols,
        "class_mapping": {str(k): v for k, v in NETWORK_CLASSES.items()},
        "metrics": comparison[best_name],
        "all_models": comparison,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "class_distribution": {
            "benign": int((y == 0).sum()),
            "attack": int((y == 1).sum()),
        },
    }
    with open(paths["metadata"], "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return meta


def analyze_network_traffic_df(
    df: pd.DataFrame,
    source_name: str = "Uploaded CSV",
    persist_history: bool = True,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """
    Run inference on a network flow DataFrame.
    Validates schema, sanitizes numeric values, runs predictions, and saves to database.
    """
    model, required_features = load_network_model()

    cleaned_df = clean_column_names(df)
    if cleaned_df.empty:
        raise ValueError("The uploaded network-flow dataset contains no records.")
    is_valid, missing_cols = validate_input_schema(cleaned_df, required_features)
    if not is_valid:
        raise ValueError(
            f"The uploaded CSV is missing {len(missing_cols)} required flow features: "
            f"{missing_cols[:5]}... Please ensure it conforms to CIC-IDS2017 schema."
        )

    # Extract & sanitize features
    feature_data = cleaned_df[required_features].copy()
    sanitized_features = sanitize_numeric_features(feature_data, feature_columns=required_features)

    # Predict
    raw_predictions = model.predict(sanitized_features)
    has_proba = hasattr(model, "predict_proba")
    probas = model.predict_proba(sanitized_features) if has_proba else None

    attack_probabilities: Optional[list[float]] = None
    if probas is not None:
        model_classes = list(getattr(model, "classes_", []))
        attack_indices = [
            index for index, value in enumerate(model_classes)
            if str(value).strip().upper() in {"1", "ATTACK"}
        ]
        if len(attack_indices) != 1:
            raise ValueError("The network model probability output does not identify one ATTACK class.")
        if probas.ndim != 2 or probas.shape[0] != len(raw_predictions):
            raise ValueError("The network model returned an invalid probability array shape.")
        attack_probabilities = [float(value) for value in probas[:, attack_indices[0]]]

    # Enrich output DataFrame
    enriched_df = df.copy()
    pred_labels = [NETWORK_CLASSES.get(int(p), "UNKNOWN") for p in raw_predictions]
    enriched_df["Predicted_Class"] = pred_labels

    attack_probs = [round(value, 4) for value in attack_probabilities] if attack_probabilities is not None else [None] * len(raw_predictions)
    row_scores = []
    risk_levels = []
    risk_severities = []
    for idx, prediction in enumerate(raw_predictions):
        predicted_attack = int(prediction) == 1
        row_score = (
            int(attack_probabilities[idx] * 100 + 0.5)
            if attack_probabilities is not None
            else (100 if predicted_attack else 0)
        )
        row_scores.append(row_score)
        risk_severities.append(DEFAULT_RISK_BANDS.classify(row_score))
        if attack_probabilities is None:
            risk_levels.append("Unknown")
        elif predicted_attack:
            risk_levels.append("High" if attack_probabilities[idx] >= 0.75 else "Medium")
        else:
            risk_levels.append("Low" if attack_probabilities[idx] <= 0.25 else "Medium")

    enriched_df["Attack_Probability"] = attack_probs
    enriched_df["Risk_Level"] = risk_levels
    enriched_df["Risk_Score"] = row_scores
    enriched_df["Risk_Severity"] = risk_severities

    # Summary analytics
    total = len(enriched_df)
    attack_count = int((raw_predictions == 1).sum())
    benign_count = int((raw_predictions == 0).sum())
    attack_pct = round((attack_count / total) * 100, 2) if total > 0 else 0.0
    overall_risk = "High" if attack_pct > 25.0 else ("Medium" if attack_pct > 5.0 else "Low")
    risk_assessment = assess_network_risk(pred_labels, attack_probabilities)
    mean_attack_probability = (
        sum(attack_probabilities) / len(attack_probabilities)
        if attack_probabilities is not None
        else None
    )

    summary = {
        "source_name": source_name,
        "total_records": total,
        "attack_records": attack_count,
        "benign_records": benign_count,
        "attack_percentage": attack_pct,
        "mean_attack_probability": mean_attack_probability,
        "overall_risk": overall_risk,
        **risk_assessment,
        "high_risk_flows": int((enriched_df["Risk_Severity"].isin(["High", "Critical"])).sum()),
        "medium_risk_flows": int((enriched_df["Risk_Severity"] == "Medium").sum()),
        "low_risk_flows": int((enriched_df["Risk_Severity"] == "Low").sum()),
    }

    if persist_history:
        save_analysis(
            analysis_type="network",
            input_summary=f"Batch: {source_name} ({total} records)",
            predicted_class="ATTACK" if attack_count > 0 else "BENIGN",
            risk_level=overall_risk,
            probability=mean_attack_probability,
            model_name="Network IDS Classifier",
            result_summary=f"Analyzed {total} network flows: {attack_count} attacks ({attack_pct}%), {benign_count} benign.",
            details=summary,
            risk_score=risk_assessment["risk_score"],
            risk_evidence=risk_assessment["risk_evidence"],
            recommendation=risk_assessment["recommendation"],
        )

    return enriched_df, summary
