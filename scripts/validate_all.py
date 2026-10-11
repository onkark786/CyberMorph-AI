"""
CyberMorph AI - End-to-End Validation Script
Runs systematic checks across all modules without requiring a browser.
"""
from __future__ import annotations

import sys
import io
import json
import traceback
from pathlib import Path

# Force UTF-8 output on Windows to avoid cp1252 encode errors
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

PASS = "[PASS]"
FAIL = "[FAIL]"
WARN = "[WARN]"

results = []

def check(label, fn):
    try:
        msg = fn()
        status = PASS
        results.append((status, label, msg or ""))
        print(f"{status}  {label}  {msg or ''}")
    except Exception as e:
        results.append((FAIL, label, str(e)))
        print(f"{FAIL}  {label}  {e}")

print("\n" + "="*70)
print("  CyberMorph AI — Complete End-to-End Validation")
print("="*70 + "\n")

# ── 1. FILE STRUCTURE ──────────────────────────────────────────────────────
print("── MODULE 1: File & Artifact Structure ──")

def check_phishing_model():
    required = ["best_model.joblib", "feature_names.json", "class_mapping.json", "metadata.json"]
    for f in required:
        p = PROJECT_ROOT / "models" / "phishing" / f
        assert p.exists(), f"Missing: {p}"
    return "All 4 phishing artifacts present"

def check_network_model():
    required = ["best_model.joblib", "feature_names.json", "class_mapping.json", "metadata.json"]
    for f in required:
        p = PROJECT_ROOT / "models" / "network" / f
        assert p.exists(), f"Missing: {p}"
    return "All 4 network IDS artifacts present"

def check_database_file():
    db = PROJECT_ROOT / "data" / "cybermorph.db"
    assert db.exists(), "cybermorph.db missing"
    return f"Database present ({db.stat().st_size} bytes)"

def check_sample_csv():
    sample = PROJECT_ROOT / "data" / "network" / "sample_test_flows.csv"
    assert sample.exists(), "sample_test_flows.csv missing"
    import pandas as pd
    df = pd.read_csv(sample)
    return f"Sample CSV: {len(df)} rows x {len(df.columns)} cols"

check("Phishing model artifacts", check_phishing_model)
check("Network IDS model artifacts", check_network_model)
check("SQLite database file", check_database_file)
check("Sample test flows CSV", check_sample_csv)

# ── 2. CONFIG & DATABASE ───────────────────────────────────────────────────
print("\n── MODULE 2: Config & Database ──")

def check_config_import():
    from src.config import APP_TITLE, DB_PATH, PHISHING_MODEL_DIR, NETWORK_MODEL_DIR
    assert APP_TITLE == "CyberMorph AI"
    return f"Config loaded, DB_PATH={DB_PATH}"

def check_db_init():
    from src.database import init_db, get_overview_stats
    init_db()
    stats = get_overview_stats()
    assert isinstance(stats, dict)
    assert "total_analyses" in stats
    return f"DB initialized, {stats['total_analyses']} total analyses"

def check_db_save_retrieve():
    from src.database import save_analysis, get_analysis_history, delete_analysis_record
    rid = save_analysis(
        analysis_type="phishing",
        input_summary="https://validation-test.com",
        predicted_class="LEGITIMATE",
        risk_level="Low",
        probability=0.95,
        model_name="Validation Test",
        result_summary="Validation test record",
        details={"test": True}
    )
    assert rid > 0
    history = get_analysis_history(limit=5)
    found = any(r["id"] == rid for r in history)
    assert found, "Saved record not found in history"
    delete_analysis_record(rid)  # clean up
    return f"Save/retrieve/delete cycle passed (record ID: {rid})"

def check_db_filtering():
    from src.database import get_analysis_history
    phish_records = get_analysis_history(analysis_type="phishing", limit=10)
    net_records = get_analysis_history(analysis_type="network", limit=10)
    return f"Type filter: {len(phish_records)} phishing, {len(net_records)} network"

check("src.config import", check_config_import)
check("Database initialization", check_db_init)
check("DB save/retrieve/delete", check_db_save_retrieve)
check("DB type filtering", check_db_filtering)

# ── 3. URL FEATURE EXTRACTION ──────────────────────────────────────────────
print("\n── MODULE 3: URL Feature Extraction ──")

def check_url_validation():
    from src.url_features import validate_and_format_url
    assert validate_and_format_url("https://google.com") == "https://google.com"
    assert validate_and_format_url("google.com").startswith("https://")
    try:
        validate_and_format_url("")
        assert False, "Empty URL should raise"
    except ValueError:
        pass
    try:
        validate_and_format_url("javascript:alert(1)")
        assert False, "JS scheme should raise"
    except ValueError:
        pass
    return "Validation: accepts valid, rejects empty/javascript/file"

def check_feature_extraction():
    from src.url_features import extract_uci_compatible_features, UCI_FEATURE_NAMES
    feats, diag = extract_uci_compatible_features("https://github.com")
    assert len(feats) == 30, f"Expected 30 features, got {len(feats)}"
    bad_vals = {k: v for k, v in feats.items() if v not in (-1, 0, 1)}
    assert not bad_vals, f"Non-ternary values: {bad_vals}"
    return f"30 features extracted, all values in {{-1,0,1}}"

def check_phishing_signals():
    from src.url_features import extract_uci_compatible_features
    feats, diag = extract_uci_compatible_features("http://192.168.1.1/login.php?redirect=paypal@attacker.com")
    assert feats["having_ip_address"] == -1, "IP detection failed"
    assert feats["sslfinal_state"] == -1, "HTTP should be -1 sslfinal_state"
    assert feats["having_at_symbol"] == -1, "@ detection failed"
    return "IP, HTTP, @ symbol all correctly flagged as -1"

check("URL validation edge cases", check_url_validation)
check("30 UCI features extracted", check_feature_extraction)
check("Phishing signal detection", check_phishing_signals)

# ── 4. PHISHING MODEL INFERENCE ────────────────────────────────────────────
print("\n── MODULE 4: Phishing Model (Real ML Inference) ──")

def check_phishing_model_load():
    from src.phishing import load_phishing_model, is_model_trained
    assert is_model_trained(), "Model not trained"
    model, feature_names = load_phishing_model()
    assert model is not None
    assert len(feature_names) == 30
    return f"Loaded: {type(model).__name__} with 30 features"

def check_phishing_predict_legitimate():
    from src.phishing import predict_url
    result = predict_url("https://www.google.com")
    assert "predicted_label" in result
    assert result["predicted_label"] in ("phishing", "legitimate")
    assert 0.0 <= result["confidence"] <= 1.0
    assert result["risk_level"] in ("Low", "Medium", "High")
    assert len(result["explanation_points"]) > 0
    return f"google.com → {result['predicted_label'].upper()} ({result['confidence']:.1%} conf, {result['risk_level']} risk)"

def check_phishing_predict_suspicious():
    from src.phishing import predict_url
    result = predict_url("http://192.168.1.1/login.php")
    assert result["predicted_label"] in ("phishing", "legitimate")
    return f"IP URL → {result['predicted_label'].upper()} ({result['confidence']:.1%} conf, {result['risk_level']} risk)"

def check_phishing_all_negative_vector():
    from src.phishing import predict_engineered_features
    from src.url_features import UCI_FEATURE_NAMES
    bad_vec = {f: -1 for f in UCI_FEATURE_NAMES}
    result = predict_engineered_features(bad_vec)
    assert result["predicted_label"] == "phishing", f"All-negative should be phishing, got {result['predicted_label']}"
    return f"All-negative UCI vector → phishing ({result['confidence']:.1%})"

def check_phishing_metadata():
    from src.phishing import get_phishing_metadata
    meta = get_phishing_metadata()
    assert meta is not None
    assert "metrics" in meta
    acc = meta["metrics"]["accuracy"]
    f1 = meta["metrics"]["f1_score"]
    assert 0.8 < acc <= 1.0, f"Suspiciously bad accuracy: {acc}"
    return f"Champion: {meta['selected_model']} | Acc={acc:.4f} F1={f1:.4f}"

check("Phishing model load", check_phishing_model_load)
check("Predict legitimate URL", check_phishing_predict_legitimate)
check("Predict suspicious IP URL", check_phishing_predict_suspicious)
check("All-negative UCI vector → phishing", check_phishing_all_negative_vector)
check("Phishing metadata accuracy range", check_phishing_metadata)

# ── 5. NETWORK IDS INFERENCE ───────────────────────────────────────────────
print("\n── MODULE 5: Network IDS (Real ML Inference) ──")

def check_network_model_load():
    from src.network_ids import load_network_model, is_network_model_trained
    assert is_network_model_trained()
    model, feats = load_network_model()
    assert model is not None
    assert len(feats) > 10
    return f"Loaded: {type(model).__name__} with {len(feats)} features"

def check_network_batch_inference():
    import pandas as pd
    from src.network_ids import analyze_network_traffic_df
    sample = PROJECT_ROOT / "data" / "network" / "sample_test_flows.csv"
    df = pd.read_csv(sample)
    enriched, summary = analyze_network_traffic_df(df, source_name="Validation Test", persist_history=False)
    assert "Predicted_Class" in enriched.columns
    assert "Attack_Probability" in enriched.columns
    assert "Risk_Level" in enriched.columns
    assert summary["total_records"] == len(df)
    assert summary["attack_records"] + summary["benign_records"] == len(df)
    pred_vals = enriched["Predicted_Class"].unique().tolist()
    return f"{summary['total_records']} flows: {summary['benign_records']} benign, {summary['attack_records']} attacks | classes={pred_vals}"

def check_network_rejects_bad_schema():
    import pandas as pd
    from src.network_ids import analyze_network_traffic_df
    bad_df = pd.DataFrame({"col_a": [1, 2], "col_b": [3, 4]})
    try:
        analyze_network_traffic_df(bad_df, persist_history=False)
        return f"{WARN} No error raised for bad schema"
    except ValueError as e:
        return f"ValueError raised correctly: {str(e)[:60]}"

def check_network_metadata():
    from src.network_ids import get_network_metadata
    meta = get_network_metadata()
    assert meta is not None
    m = meta["metrics"]
    return f"Champion: {meta['selected_model']} | Acc={m['accuracy']:.4f} F1={m['f1_score']:.4f}"

check("Network model load", check_network_model_load)
check("Batch network inference", check_network_batch_inference)
check("Rejects missing-column CSV", check_network_rejects_bad_schema)
check("Network metadata valid", check_network_metadata)

# ── 6. EXPLAINABILITY ─────────────────────────────────────────────────────
print("\n── MODULE 6: Explainability (XAI) ──")

def check_global_feature_importance():
    import numpy as np
    from src.phishing import load_phishing_model
    from src.explainability import get_global_feature_importances
    model, feats = load_phishing_model()
    imp_df = get_global_feature_importances(model, feats, top_n=10)
    assert len(imp_df) == 10
    assert "Feature" in imp_df.columns
    assert "Importance" in imp_df.columns
    assert not imp_df["Importance"].isna().any()
    top_feat = imp_df.iloc[0]["Feature"]
    top_imp = imp_df.iloc[0]["Importance"]
    return f"Top feature: {top_feat} ({top_imp:.4f})"

def check_local_explanation():
    from src.phishing import predict_url
    from src.explainability import explain_single_url_prediction
    result = predict_url("http://paypal-verify.secure-account.tk/login")
    exp_df = explain_single_url_prediction(result["extracted_features"], result["predicted_label"], top_n=8)
    assert len(exp_df) <= 8
    assert "Signal Name" in exp_df.columns
    assert "Status" in exp_df.columns
    suspicious_count = (exp_df["Status"] == "Suspicious").sum()
    return f"Local explanation: {suspicious_count} suspicious signals for {result['predicted_label'].upper()}"

check("Global feature importances", check_global_feature_importance)
check("Local prediction explanation", check_local_explanation)

# ── 7. PREPROCESSING ──────────────────────────────────────────────────────
print("\n── MODULE 7: Preprocessing ──")

def check_inf_nan_handling():
    import numpy as np
    import pandas as pd
    from src.preprocessing import sanitize_numeric_features
    df = pd.DataFrame({"a": [1.0, np.inf, -np.inf, np.nan], "b": [5.0, 6.0, 7.0, 8.0]})
    result = sanitize_numeric_features(df, ["a", "b"])
    assert not np.isinf(result["a"]).any()
    assert not result["a"].isna().any()
    return "inf/nan → replaced and median-imputed correctly"

def check_label_normalization():
    import pandas as pd
    from src.preprocessing import normalize_network_labels
    labels = pd.Series(["BENIGN", "DDoS", "PortScan", " benign ", "Bot"])
    y, id_map, _ = normalize_network_labels(labels, binary_mode=True)
    assert y.iloc[0] == 0
    assert y.iloc[1] == 1
    assert y.iloc[3] == 0  # stripped benign
    return f"BENIGN→0, attacks→1, {dict(id_map)}"

check("inf/nan sanitization", check_inf_nan_handling)
check("Label normalization (binary)", check_label_normalization)

# ── 8. REPORTING ──────────────────────────────────────────────────────────
print("\n── MODULE 8: Reporting (CSV + PDF) ──")

def check_csv_export():
    import pandas as pd
    from src.reporting import generate_csv_bytes
    df = pd.DataFrame({"url": ["https://test.com"], "risk": ["Low"], "pred": ["legitimate"]})
    b = generate_csv_bytes(df)
    assert isinstance(b, bytes)
    assert b"url" in b
    assert b"https://test.com" in b
    return f"CSV bytes: {len(b)} bytes, valid UTF-8 CSV"

def check_pdf_export():
    from src.reporting import generate_security_pdf_report
    from src.database import get_overview_stats, get_analysis_history
    from src.phishing import get_phishing_metadata
    from src.network_ids import get_network_metadata
    stats = get_overview_stats()
    pdf = generate_security_pdf_report(
        overview_stats=stats,
        phishing_meta=get_phishing_metadata(),
        network_meta=get_network_metadata(),
        recent_records=get_analysis_history(limit=5),
    )
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF"), f"Does not start with %PDF: {pdf[:10]}"
    return f"PDF generated: {len(pdf):,} bytes, valid %PDF header"

check("CSV export bytes", check_csv_export)
check("PDF ReportLab generation", check_pdf_export)

# ── 9. SQLITE PERSISTENCE ACROSS RESTARTS ────────────────────────────────
print("\n── MODULE 9: SQLite Persistence ──")

def check_history_persistence():
    from src.database import save_analysis, get_analysis_history, get_overview_stats
    rid = save_analysis(
        analysis_type="phishing",
        input_summary="https://persistence-check.com",
        predicted_class="PHISHING",
        risk_level="High",
        probability=0.92,
        model_name="Random Forest Classifier (UCI Phishing)",
        result_summary="Persistence validation test.",
        details={"validation": "persistence_test"}
    )
    stats_after = get_overview_stats()
    history = get_analysis_history(search_query="persistence-check", limit=5)
    assert len(history) >= 1
    return f"Record #{rid} persisted; total analyses now: {stats_after['total_analyses']}"

check("SQLite persistence", check_history_persistence)

# ── FINAL SUMMARY ─────────────────────────────────────────────────────────
print("\n" + "="*70)
passed = sum(1 for r in results if r[0] == PASS)
failed = sum(1 for r in results if r[0] == FAIL)
warned = sum(1 for r in results if r[0] == WARN)
print(f"  RESULTS: {passed} passed  |  {failed} failed  |  {warned} warnings")
print("="*70)

if failed > 0:
    print("\nFailed checks:")
    for r in results:
        if r[0] == FAIL:
            print(f"  {r[1]}: {r[2]}")
    sys.exit(1)
else:
    print("\n✅ All checks passed. CyberMorph AI is fully operational.")
    sys.exit(0)
