from __future__ import annotations

import json
from pathlib import Path

from phishing_model import train_and_save_phishing_model


if __name__ == "__main__":
    results = train_and_save_phishing_model()
    print("Phishing model training complete.")
    print(json.dumps(results, indent=2, default=str))
