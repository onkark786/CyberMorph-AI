from __future__ import annotations

from pathlib import Path
import streamlit as st

from src.analysis_digs import (
    create_signal_waterfall_dig,
    create_threat_gauge,
    create_url_threat_radar,
)
from src.config import APP_TITLE, PROJECT_ROOT
from src.database import save_analysis
from src.explainability import explain_single_url_prediction
from src.phishing import (
    is_model_trained,
    predict_engineered_features,
    predict_url,
)
from src.ui_theme import (
    apply_custom_theme,
    render_analysis_dig_box,
    render_brand_sidebar,
    render_page_header,
)
from src.url_features import UCI_FEATURE_NAMES, get_feature_descriptions

st.set_page_config(
    page_title=f"{APP_TITLE} | Phishing Detection",
    page_icon="🎣",
    layout="wide",
)

apply_custom_theme()
render_brand_sidebar()

# Page Header
render_page_header(
    title="Phishing URL Deception & Lexical Scanner",
    subtitle="Passive lexical inspection, multi-vector threat radar, and explainable signal diagnostics.",
    icon="🎣",
)

# Header Visual Graphic
scanner_art_path = PROJECT_ROOT / "assets" / "phishing_scanner.jpg"
if scanner_art_path.exists():
    st.image(str(scanner_art_path), use_container_width=True)

if not is_model_trained():
    st.error("⚠️ Phishing detection model is not trained yet!")
    st.info("Train the model by executing `python scripts/train_phishing_model.py` in PowerShell.")
    st.stop()

tab_url, tab_engineered = st.tabs(["🌐 Live URL Telemetry Scanner", "🔬 Academic UCI Feature Lab"])

with tab_url:
    st.markdown("### Safe Lexical URL Evaluation")
    st.caption(
        "Analyzes domain lexical patterns, host structures, and protocol markers without establishing remote connections to hostile hosts."
    )

    url_input = st.text_input(
        "Enter Target Website URL:",
        placeholder="https://secure-login-paypal.com.verify-account.tk",
        help="Paste a URL or domain. Missing http/https scheme will be defaulted safely.",
    )

    col_btn, col_sample = st.columns([1, 3])
    with col_btn:
        analyze_clicked = st.button("🔍 Scan & Analyze URL", use_container_width=True)
    with col_sample:
        st.markdown(
            "**Quick Test Samples:** "
            "`https://paypal.com` (Legitimate) • "
            "`http://192.168.1.1/login.php` (IP Phishing) • "
            "`http://bit.ly/bank-security-update` (Shortener) • "
            "`http://apple-id-verify.com.account-update.tk` (Subdomain spoof)"
        )

    if analyze_clicked:
        if not url_input.strip():
            st.warning("Please provide a non-empty URL string.")
        else:
            try:
                with st.spinner("Executing passive lexical parsing and ML inference..."):
                    result = predict_url(url_input)

                # Persist to database
                save_analysis(
                    analysis_type="phishing",
                    input_summary=result["url"],
                    predicted_class=result["predicted_label"].upper(),
                    risk_level=result["risk_level"],
                    probability=result["confidence"],
                    model_name="Random Forest Classifier (UCI Phishing)",
                    result_summary=result["summary"],
                    details={
                        "confidence": result["confidence"],
                        "diagnostics": result["diagnostics"],
                        "explanation_points": result["explanation_points"],
                    },
                )

                st.divider()

                # Result KPI Banner
                is_phish = result["predicted_label"] == "phishing"
                c1, c2, c3, c4 = st.columns(4)

                c1.metric(
                    "Classification",
                    result["predicted_label"].upper(),
                    delta="Threat Detected" if is_phish else "Benign Structure",
                    delta_color="inverse" if is_phish else "normal",
                )
                c2.metric("Assessed Risk", result["risk_level"].upper())
                c3.metric("Model Confidence", f"{result['confidence']:.2%}")
                c4.metric("Extracted Lexical Signals", len(result["extracted_features"]))

                # Recommended Action Alert
                if is_phish:
                    st.error(
                        "🛑 **Threat Alert: Weaponized Phishing Signatures Identified!**\n\n"
                        "- **Recommendation:** Do NOT enter credentials or download attachments from this domain.\n"
                        "- **Defensive Action:** Quarantine URL and add domain to organizational perimeter blocklist."
                    )
                else:
                    st.success(
                        "✅ **Low Risk: Conforms to Standard Legitimate Naming Conventions.**\n\n"
                        "- **Notice:** While lexical structure conforms to benign baselines, always inspect SSL certificate authenticity."
                    )

                # Deep Analysis Digs: Gauge + Radar
                st.divider()
                st.subheader("🎯 Visual Analysis Digs")

                threat_pct = (result["confidence"] * 100) if is_phish else ((1.0 - result["confidence"]) * 100)
                col_g, col_rad = st.columns([1, 1.2])

                with col_g:
                    gauge_fig = create_threat_gauge(
                        risk_percentage=round(threat_pct, 1),
                        title="URL Threat Probability Score",
                    )
                    st.plotly_chart(gauge_fig, use_container_width=True)

                with col_rad:
                    radar_fig = create_url_threat_radar(result["extracted_features"])
                    st.plotly_chart(radar_fig, use_container_width=True)

                render_analysis_dig_box(
                    title="Analysis Dig: Interpreting the 5-Pillar Threat Radar",
                    explanation="The Threat Radar maps the target across five critical deception vectors (0 = clean, 100 = extreme risk):",
                    takeaways=[
                        "Host / IP Deception: Spikes when an IP address replaces a trusted domain to bypass reputation lookups.",
                        "Domain Spoofing: Flags excessive subdomain nesting or hyphens imitating reputable brand names.",
                        "Protocol / SSL Risk: Highlights plain HTTP, self-signed tokens, or misleading 'https' domain substrings.",
                        "Lexical Obfuscation: Detects unusually long URLs (>75 chars) and shortened redirect services.",
                        "Redirection Masking: Highlights '@' symbols and '//' path tricks used to divert traffic.",
                    ],
                )

                # Feature Impact Waterfall Dig
                st.divider()
                st.subheader("📊 Signal Impact Waterfall Dig")
                explanation_df = explain_single_url_prediction(
                    result["extracted_features"],
                    result["predicted_label"],
                    top_n=8,
                )

                col_wf, col_diag = st.columns([1.2, 1])
                with col_wf:
                    wf_fig = create_signal_waterfall_dig(explanation_df)
                    st.plotly_chart(wf_fig, use_container_width=True)

                with col_diag:
                    st.markdown("##### Detailed Signal Diagnostics")
                    for pt in result["explanation_points"]:
                        st.markdown(f"- {pt}")

                    if result["probability_map"]:
                        st.markdown("##### Class Probability Distribution")
                        for cls_name, p_val in result["probability_map"].items():
                            st.progress(p_val, text=f"{cls_name.capitalize()}: {p_val:.2%}")

                # Full Feature Inspection Accordion
                with st.expander("🔍 Inspect All 30 Extracted UCI Features"):
                    st.json(result["extracted_features"])

            except Exception as exc:
                st.error(f"Analysis failed: {exc}")

with tab_engineered:
    st.markdown("### UCI Phishing Websites Feature Tester")
    st.caption(
        "Directly test arbitrary 30-feature vectors (-1: Phishing, 0: Suspicious, 1: Legitimate) to test the trained model on exact UCI benchmarks."
    )

    feature_meta = get_feature_descriptions()

    col_f1, col_f2 = st.columns(2)
    custom_vector = {col: 1 for col in UCI_FEATURE_NAMES}

    with col_f1:
        st.markdown("##### Primary Structural Features")
        custom_vector["having_ip_address"] = st.selectbox(
            "1. having_ip_address", [1, -1], index=0, format_func=lambda x: "1: Normal Domain" if x == 1 else "-1: IP Hostname"
        )
        custom_vector["url_length"] = st.selectbox(
            "2. url_length", [1, 0, -1], index=0, format_func=lambda x: "1: <54 chars" if x == 1 else ("0: 54-75 chars" if x == 0 else "-1: >75 chars")
        )
        custom_vector["shortining_service"] = st.selectbox(
            "3. shortining_service", [1, -1], index=0, format_func=lambda x: "1: Full URL" if x == 1 else "-1: Shortened URL"
        )
        custom_vector["having_at_symbol"] = st.selectbox(
            "4. having_at_symbol", [1, -1], index=0, format_func=lambda x: "1: No '@'" if x == 1 else "-1: Contains '@'"
        )
        custom_vector["prefix_suffix"] = st.selectbox(
            "5. prefix_suffix (hyphen)", [1, -1], index=0, format_func=lambda x: "1: No Hyphen" if x == 1 else "-1: Contains Hyphen"
        )

    with col_f2:
        st.markdown("##### Protocol & Domain Features")
        custom_vector["having_sub_domain"] = st.selectbox(
            "6. having_sub_domain", [1, 0, -1], index=0, format_func=lambda x: "1: Single Subdomain" if x == 1 else ("0: Dual Subdomain" if x == 0 else "-1: Multiple Subdomains")
        )
        custom_vector["sslfinal_state"] = st.selectbox(
            "7. sslfinal_state", [1, 0, -1], index=0, format_func=lambda x: "1: Trusted HTTPS" if x == 1 else ("0: Suspicious HTTPS" if x == 0 else "-1: HTTP Unencrypted")
        )
        custom_vector["https_token"] = st.selectbox(
            "8. https_token in domain", [1, -1], index=0, format_func=lambda x: "1: Legitimate" if x == 1 else "-1: Misleading 'https' token"
        )
        custom_vector["port"] = st.selectbox(
            "9. port", [1, -1], index=0, format_func=lambda x: "1: Standard (80/443)" if x == 1 else "-1: Non-standard Port"
        )
        custom_vector["web_traffic"] = st.selectbox(
            "10. web_traffic ranking", [1, 0, -1], index=0, format_func=lambda x: "1: High Traffic" if x == 1 else ("0: Medium Traffic" if x == 0 else "-1: Low / Unknown Traffic")
        )

    if st.button("🧪 Predict Engineered Feature Vector", use_container_width=True):
        res_eng = predict_engineered_features(custom_vector)
        st.success(f"**Classification Output:** {res_eng['predicted_label'].upper()}")
        st.metric("Model Confidence", f"{res_eng['confidence']:.2%}")
        st.write("Full Class Probabilities:", res_eng["probability_map"])
