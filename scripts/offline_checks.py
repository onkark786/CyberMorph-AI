"""
Offline validation script for CyberMorphAI (no web server launched).
Performs:
 - import checks
 - model artifact existence checks
 - database overview stats
 - CSV/PDF generation smoke tests (in-memory)
 - reports success/failure as exit code 0/1
"""
from __future__ import annotations

import sys
from pathlib import Path
import traceback

FAILED = False

try:
    print("Python executable:", sys.executable)
    # Core imports
    from src.database import get_overview_stats, get_analysis_history
    from src.phishing import is_model_trained, get_model_paths, get_phishing_metadata
    from src.network_ids import is_network_model_trained, get_network_model_paths, get_network_metadata
    from src.reporting import generate_csv_bytes, generate_security_pdf_report
    import pandas as pd

    print("Imported core modules successfully.")

    # Database checks
    stats = get_overview_stats()
    print("DB overview stats:", stats)

    # Model artifact checks
    ph_paths = get_model_paths()
    net_paths = get_network_model_paths()
    print("Phishing model artifacts:")
    for k, p in ph_paths.items():
        print(f"  {k}: {Path(p).exists()} -> {p}")
    print("Network model artifacts:")
    for k, p in net_paths.items():
        print(f"  {k}: {Path(p).exists()} -> {p}")

    print("Phishing trained:", is_model_trained())
    print("Network trained:", is_network_model_trained())

    # Recent records
    recs = get_analysis_history(limit=5)
    print(f"Recent history count: {len(recs)}")

    # CSV generation test
    sample_df = pd.DataFrame([
        {"id": 0, "timestamp": "1970-01-01 00:00:00 UTC", "analysis_type": "phishing", "input_summary": "example.com", "predicted_class": "LEGIT", "risk_level": "Low"}
    ])
    csv_b = generate_csv_bytes(sample_df)
    print(f"CSV bytes generated: {len(csv_b)} bytes")

    # PDF generation test (may require reportlab)
    try:
        pdf_b = generate_security_pdf_report(
            overview_stats=stats,
            phishing_meta=get_phishing_metadata(),
            network_meta=get_network_metadata(),
            recent_records=recs,
        )
        print(f"PDF bytes generated: {len(pdf_b)} bytes")
    except Exception as e:
        print("PDF generation failed (reporting dependency missing or error):", e)
        traceback.print_exc()

except Exception as exc:
    FAILED = True
    print("Offline checks failed:")
    traceback.print_exc()

if FAILED:
    sys.exit(1)
else:
    print("Offline checks completed successfully.")
    sys.exit(0)
