"""Produce a machine-readable offline validation summary (JSON).
"""
import json
import sys
from pathlib import Path

summary = {"errors": [], "warnings": [], "results": {}}

try:
	from src.database import get_overview_stats, get_analysis_history
	from src.phishing import is_model_trained, get_model_paths, get_phishing_metadata
	from src.network_ids import is_network_model_trained, get_network_model_paths, get_network_metadata
	from src.reporting import generate_csv_bytes, generate_security_pdf_report
	import pandas as pd

	summary["results"]["db_overview"] = get_overview_stats()
	ph_paths = get_model_paths()
	net_paths = get_network_model_paths()
	summary["results"]["phishing_artifacts"] = {k: Path(p).exists() for k, p in ph_paths.items()}
	summary["results"]["network_artifacts"] = {k: Path(p).exists() for k, p in net_paths.items()}
	summary["results"]["phishing_trained"] = is_model_trained()
	summary["results"]["network_trained"] = is_network_model_trained()

	recent = get_analysis_history(limit=5)
	summary["results"]["recent_count"] = len(recent)

	# CSV test
	sample_df = pd.DataFrame([{"id": 0, "timestamp": "1970-01-01 00:00:00 UTC", "analysis_type": "phishing", "input_summary": "example.com", "predicted_class": "LEGIT", "risk_level": "Low"}])
	csv_b = generate_csv_bytes(sample_df)
	summary["results"]["csv_bytes"] = len(csv_b)

	# PDF test (non-fatal)
	try:
		pdf_b = generate_security_pdf_report(
			overview_stats=summary["results"]["db_overview"],
			phishing_meta=get_phishing_metadata(),
			network_meta=get_network_metadata(),
			recent_records=recent,
		)
		summary["results"]["pdf_bytes"] = len(pdf_b)
	except Exception as e:
		summary["warnings"].append(f"PDF generation failed: {e}")

except Exception as exc:
	summary["errors"].append(str(exc))

out_path = Path("scripts/offline_summary.json")
out_path.write_text(json.dumps(summary, indent=2))
print("WROTE", out_path)
sys.exit(0 if not summary["errors"] else 2)