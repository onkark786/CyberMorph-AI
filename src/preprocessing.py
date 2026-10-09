from __future__ import annotations

import re
from typing import Any, Optional

import numpy as np
import pandas as pd


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace, control characters, and normalize column headers."""
    cleaned = df.copy()
    cleaned.columns = [
        re.sub(r"\s+", " ", str(col).strip())
        for col in cleaned.columns
    ]
    return cleaned


def sanitize_numeric_features(
    df: pd.DataFrame,
    feature_columns: Optional[list[str]] = None,
    replace_inf: bool = True,
    fill_missing: bool = True,
) -> pd.DataFrame:
    """
    Sanitize numeric features by replacing +/- inf with finite bounds/NaN
    and imputing missing values.
    """
    cleaned = df.copy()
    cols = feature_columns if feature_columns is not None else cleaned.columns.tolist()

    for col in cols:
        if col not in cleaned.columns:
            continue

        # Coerce to numeric
        cleaned[col] = pd.to_numeric(cleaned[col], errors="coerce")

        if replace_inf:
            cleaned[col] = cleaned[col].replace([np.inf, -np.inf], np.nan)

        if fill_missing:
            # Impute NaN with median or 0.0
            col_median = cleaned[col].median()
            impute_val = col_median if pd.notna(col_median) else 0.0
            cleaned[col] = cleaned[col].fillna(impute_val)

    return cleaned


def normalize_network_labels(
    y: pd.Series,
    binary_mode: bool = True,
) -> tuple[pd.Series, dict[int, str], dict[str, int]]:
    """
    Normalize raw CIC-IDS2017 labels.
    Binary mode maps 'BENIGN' (case/whitespace insensitive) -> 0, and all attacks -> 1.
    Returns:
        1. normalized target Series
        2. id_to_label mapping
        3. label_to_id mapping
    """
    cleaned_y = y.astype(str).str.strip()

    if binary_mode:
        is_attack = cleaned_y.apply(lambda val: 0 if val.upper() == "BENIGN" else 1)
        id_to_label = {0: "BENIGN", 1: "ATTACK"}
        label_to_id = {"BENIGN": 0, "ATTACK": 1}
        return is_attack.astype(int), id_to_label, label_to_id
    else:
        unique_labels = sorted(cleaned_y.unique())
        label_to_id = {lbl: i for i, lbl in enumerate(unique_labels)}
        id_to_label = {i: lbl for lbl, i in label_to_id.items()}
        numeric_y = cleaned_y.map(label_to_id).astype(int)
        return numeric_y, id_to_label, label_to_id


def validate_input_schema(
    df: pd.DataFrame,
    required_features: list[str],
) -> tuple[bool, list[str]]:
    """
    Validate that an input dataframe contains all required features.
    Returns (is_valid, missing_columns).
    """
    cleaned_df = clean_column_names(df)
    existing_cols = set(cleaned_df.columns)
    missing = [col for col in required_features if col not in existing_cols]
    return len(missing) == 0, missing
