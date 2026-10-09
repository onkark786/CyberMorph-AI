from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from src.config import NETWORK_DATA_DIR, PHISHING_DATA_DIR
from src.phishing import fetch_or_load_dataset


def inspect_phishing():
    print("-" * 50)
    print("INSPECTING UCI PHISHING WEBSITES DATASET")
    print("-" * 50)
    try:
        df = fetch_or_load_dataset()
        print(f"Shape: {df.shape[0]} rows, {df.shape[1]} columns")
        print("\nTarget Label Distribution:")
        print(df["result"].value_counts())
        print(f"\nMissing values total: {df.isna().sum().sum()}")
        print(f"Features: {list(df.columns[:10])}... ({len(df.columns) - 1} total)")
    except Exception as exc:
        print(f"Could not inspect phishing dataset: {exc}")


def inspect_network():
    print("\n" + "-" * 50)
    print("INSPECTING CIC-IDS2017 NETWORK DATASET")
    print("-" * 50)
    candidates = list(NETWORK_DATA_DIR.glob("*.csv"))
    if not candidates:
        print("No network CSV files found in data/network/. Run scripts/generate_sample_data.py first.")
        return

    for c in candidates:
        print(f"\nFile: {c.name}")
        df = pd.read_csv(c, nrows=100)
        print(f"Columns count: {len(df.columns)}")
        label_col = next((col for col in df.columns if col.strip().lower() == "label"), None)
        if label_col:
            full_df = pd.read_csv(c)
            print(f"Total rows: {len(full_df)}")
            print("Label Distribution:")
            print(full_df[label_col].value_counts())
        else:
            print("No 'Label' column (inference sample)")


if __name__ == "__main__":
    inspect_phishing()
    inspect_network()
