from __future__ import annotations

import streamlit as st

from src.config import APP_TITLE
from src.database import save_analysis
from src.explainability import create_local_explanation_plot, explain_single_url_prediction
from src.phishing import (
    is_model_trained,
    predict_engineered_features,
    predict_url,
)
from src.ui_theme import apply_custom_theme, render_brand_sidebar, render_page_header
from src.url_features import UCI_FEATURE_NAMES, get_feature_descriptions

st.set_page_config(
    page_title=f"{APP_TITLE} | Phishing Detection",
    page_icon="🎣",
    layout="wide",
)

apply_custom_theme()
render_brand_sidebar()

render_page_header(
    title="Phishing URL Detection Engine",
    subtitle="Machine learning-based lexical inspection, risk assessment, and explainable feature signals.",
    icon="🎣",
)

if not is_model_trained():
    st.error("⚠️ Phishing detection model is not trained yet!")
    st.info("Train the model by executing `python scripts/train_phishing_model.py` in PowerShell.")
    st.stop()

tab_url, tab_engineered = st.tabs(["🌐 Live URL Analysis", "🔬 Engineered Feature Lab (Academic / UCI)"])

with tab_url:
    st.markdown("### Safe Lexical URL Evaluation")
    st.caption(
        "Evaluates domain, path, and protocol characteristics passively without establishing an active remote connection to untrusted servers."
    )

    url_input = st.text_input(
        "Enter Target Website URL:",
        placeholder="https://secure-login-paypal.com.verify-account.tk",
        help="Paste a URL or domain. Leading http/https scheme will be defaulted safely if omitted.",
    )

    col_btn, col_sample = st.columns([1, 3])
    with col_btn:
        analyze_clicked = st.button("🔍 Analyze URL")
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
                        "risk_score": result["risk_score"],
                        "risk_severity": result["risk_severity"],
                        "risk_evidence": result["risk_evidence"],
                        "recommendation": result["recommendation"],
                        "diagnostics": result["diagnostics"],
                        "explanation_points": result["explanation_points"],
                    },
                    risk_score=result["risk_score"],
                    risk_evidence=result["risk_evidence"],
                    recommendation=result["recommendation"],
                )

                st.divider()

                # Result KPI Banner
                is_phish = result["predicted_label"] == "phishing"
                c1, c2, c3, c4, c5 = st.columns(5)

                c1.metric(
                    "Classification",
                    result["predicted_label"].upper(),
                    delta="Threat Detected" if is_phish else "Benign Structure",
                    delta_color="inverse" if is_phish else "normal",
                )
                c2.metric("Assessed Risk", result["risk_level"].upper())
                c3.metric("Model Confidence", f"{result['confidence']:.2%}")
                c4.metric("Extracted Lexical Signals", len(result["extracted_features"]))
                c5.metric("Unified Risk Score", f"{result['risk_score']}/100 · {result['risk_severity']}")
                st.caption("The unified score is a model-derived risk index, not a calibrated probability or a guarantee of safety.")

                # Recommended Action Alert
                if is_phish:
                    st.error(
                        "🛑 **Threat Alert: High Risk Phishing Indicators Identified!**\n\n"
                        "- **Recommendation:** Do NOT visit this link or enter personal credentials.\n"
                        "- **Defensive Action:** Block domain at firewall/DNS gateway and report to security operations."
                    )
                else:
                    st.success(
                        "✅ **Low Risk: Conforms to Standard Legitimate Naming Conventions.**\n\n"
                        "- **Notice:** While lexical structure appears normal, always verify SSL certificate authenticity before submitting confidential data."
                    )

                # Local Explanation Breakdown
                st.subheader("💡 Explainable Prediction Signals")
                explanation_df = explain_single_url_prediction(
                    result["extracted_features"],
                    result["predicted_label"],
                    top_n=8,
                )

                col_exp_chart, col_exp_table = st.columns([1, 1])
                with col_exp_chart:
                    exp_fig = create_local_explanation_plot(
                        explanation_df,
                        title=f"Feature Impact on Classification ({result['url']})",
                    )
                    st.plotly_chart(exp_fig, width='stretch')

                with col_exp_table:
                    st.markdown("##### Detailed Signal Diagnostics")
                    for pt in result["explanation_points"]:
                        st.markdown(f"- {pt}")
                    st.markdown(f"**Defensive recommendation:** {result['recommendation']}")

                    if result["probability_map"]:
                        st.markdown("##### Class Probability Distribution")
                        for cls_name, p_val in result["probability_map"].items():
                            # show a simple percentage bar and label
                            st.write(f"{cls_name.capitalize()}: {p_val:.2%}")

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

    if st.button("🧪 Predict Engineered Feature Vector"):
        res_eng = predict_engineered_features(custom_vector)
        st.success(f"**Classification Output:** {res_eng['predicted_label'].upper()}")
        st.metric("Model Confidence", f"{res_eng['confidence']:.2%}")
        st.write("Full Class Probabilities:", res_eng["probability_map"])
