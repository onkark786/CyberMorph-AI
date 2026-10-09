from __future__ import annotations

import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.network_ids import train_network_pipeline

if __name__ == "__main__":
    print("=" * 60)
    print("Starting CyberMorph AI — Network Intrusion Detection Training Pipeline")
    print("Dataset: CIC-IDS2017 Flow Records")
    print("Comparing: Logistic Regression, Decision Tree, Random Forest")
    print("=" * 60)

    try:
        results = train_network_pipeline()
        print("\nNetwork IDS Training completed successfully!")
        print(f"Selected Champion Model: {results['selected_model']}")
        print(f"Test Accuracy:  {results['metrics']['accuracy']:.4f}")
        print(f"Test Precision: {results['metrics']['precision']:.4f}")
        print(f"Test Recall:    {results['metrics']['recall']:.4f}")
        print(f"Test F1-Score:  {results['metrics']['f1_score']:.4f}")
        print("\nSaved artifacts to models/network/ and logged run to SQLite.")
    except Exception as exc:
        print(f"\n[ERROR] Network IDS training failed: {exc}")
        sys.exit(1)
