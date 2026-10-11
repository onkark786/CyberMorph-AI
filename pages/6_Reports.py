from __future__ import annotations

import pandas as pd
import streamlit as st

from src.config import APP_TITLE
from src.database import get_analysis_history, get_overview_stats
from src.network_ids import get_network_metadata
from src.phishing import get_phishing_metadata
from src.reporting import generate_csv_bytes, generate_security_pdf_report
from src.ui_theme import apply_custom_theme, render_brand_sidebar, render_page_header

st.set_page_config(
    page_title=f"{APP_TITLE} | Security Reports",
    page_icon="📄",
    layout="wide",
)

apply_custom_theme()
render_brand_sidebar()

render_page_header(
    title="Security Intelligence Reports & Compliance Export",
    subtitle="Generate formatted executive audit reports, metric digests, and audit logs.",
    icon="📄",
)

# Fetch latest telemetry data
stats = get_overview_stats()
phish_meta = get_phishing_metadata()
net_meta = get_network_metadata()
recent_records = get_analysis_history(limit=15)

col_pdf, col_csv = st.columns(2)

with col_pdf:
    st.subheader("📑 Formal PDF Threat Intelligence Report")
    st.markdown(
        """
        Generates an academic-grade, publication-ready PDF document including:
        - Executive Threat Overview & KPIs
        - Phishing & Network Detection distributions
        - Empirical ML evaluation metrics (Accuracy, Precision, Recall, F1)
        - Audit trail log of recent evaluations
        - Educational safety disclaimers & academic limitations
        """
    )

    if st.button("🔨 Compile PDF Security Report"):
        with st.spinner("Compiling ReportLab PDF document..."):
            pdf_bytes = generate_security_pdf_report(
                overview_stats=stats,
                phishing_meta=phish_meta,
                network_meta=net_meta,
                recent_records=recent_records,
            )
        st.session_state["cached_pdf"] = pdf_bytes
        st.success("✅ PDF Report successfully compiled!")

    if "cached_pdf" in st.session_state:
        st.download_button(
            label="⬇️ Download CyberMorph_AI_Security_Report.pdf",
            data=st.session_state["cached_pdf"],
            file_name="CyberMorph_AI_Security_Report.pdf",
            mime="application/pdf",
        )

with col_csv:
    st.subheader("📊 Structured Data Export (CSV)")
    st.markdown(
        """
        Export tabular data for downstream reporting, spreadsheet analysis, or academic viva review:
        """
    )

    history_all = get_analysis_history(limit=500)
    if history_all:
        h_df = pd.DataFrame(history_all)[[
            "id", "timestamp", "analysis_type", "input_summary",
            "predicted_class", "risk_level", "probability", "model_name", "result_summary"
        ]]
        hist_csv = generate_csv_bytes(h_df)
        st.download_button(
            label="📥 Export Full Analysis History (CSV)",
            data=hist_csv,
            file_name="cybermorph_full_history.csv",
            mime="text/csv",
        )

    # Export Model Evaluation Metrics
    eval_records = []
    if phish_meta and "metrics" in phish_meta:
        m = phish_meta["metrics"]
        eval_records.append({
            "Domain": "Phishing Detection",
            "Champion": phish_meta.get("selected_model", ""),
            "Accuracy": m.get("accuracy", 0.0),
            "Precision": m.get("precision", 0.0),
            "Recall": m.get("recall", 0.0),
            "F1_Score": m.get("f1_score", 0.0),
        })
    if net_meta and "metrics" in net_meta:
        m = net_meta["metrics"]
        eval_records.append({
            "Domain": "Network Intrusion",
            "Champion": net_meta.get("selected_model", ""),
            "Accuracy": m.get("accuracy", 0.0),
            "Precision": m.get("precision", 0.0),
            "Recall": m.get("recall", 0.0),
            "F1_Score": m.get("f1_score", 0.0),
        })

    if eval_records:
        eval_df = pd.DataFrame(eval_records)
        eval_csv = generate_csv_bytes(eval_df)
        st.download_button(
            label="📥 Export Model Evaluation Metrics (CSV)",
            data=eval_csv,
            file_name="cybermorph_model_benchmarks.csv",
            mime="text/csv",
        )

st.divider()

# Live Preview of Report Contents
st.subheader("👀 Report Summary Live Preview")
c1, c2, c3 = st.columns(3)
c1.metric("Total Recorded Sessions", stats["total_analyses"])
c2.metric("Total Malicious Detections", stats["malicious_phishing"] + stats["attack_network_flows"])
c3.metric("High-Risk Alerts", stats["high_risk_count"])

with st.expander("📋 Preview Recent Audit Trail Included in Report"):
    if recent_records:
        st.dataframe(pd.DataFrame(recent_records)[[
            "id", "timestamp", "analysis_type", "input_summary", "predicted_class", "risk_level"
        ]], width='stretch')
    else:
        st.write("No recorded events currently in database.")
