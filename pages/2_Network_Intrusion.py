from __future__ import annotations

import io
from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st

from src.config import APP_TITLE, NETWORK_DATA_DIR
from src.network_ids import (
    analyze_network_traffic_df,
    is_network_model_trained,
    load_network_model,
)
from src.reporting import generate_csv_bytes
from src.ui_theme import apply_custom_theme, render_brand_sidebar, render_page_header

st.set_page_config(
    page_title=f"{APP_TITLE} | Network Intrusion Detection",
    page_icon="🌐",
    layout="wide",
)

apply_custom_theme()
render_brand_sidebar()

render_page_header(
    title="Network Intrusion Detection System (NIDS)",
    subtitle="Flow-based telemetry analytics, anomaly classification, and batch intrusion diagnostics.",
    icon="🌐",
)

if not is_network_model_trained():
    st.error("⚠️ Network intrusion detection model is not trained yet!")
    st.info("Train the model by executing `python scripts/train_network_model.py` in PowerShell.")
    st.stop()

# Helper sample download
sample_file_path = NETWORK_DATA_DIR / "sample_test_flows.csv"
if sample_file_path.exists():
    with open(sample_file_path, "rb") as f:
        sample_bytes = f.read()
    st.download_button(
        label="📥 Download Sample CIC-IDS2017 Test CSV (50 Flows)",
        data=sample_bytes,
        file_name="sample_test_flows.csv",
        mime="text/csv",
        help="Use this ready-to-test CSV file if you don't have your own network capture file.",
    )

st.divider()

uploaded_file = st.file_uploader(
    "Upload Network Flow Records (CSV Format):",
    type=["csv"],
    help="Upload a CSV file containing standard CIC-IDS2017 / CICFlowMeter network flow features.",
)

if uploaded_file is not None:
    try:
        raw_df = pd.read_csv(uploaded_file)
        st.subheader("📋 Dataset Preview & Schema Inspection")
        st.caption(f"Loaded **{len(raw_df)}** records with **{len(raw_df.columns)}** columns.")
        if raw_df.empty:
            st.error("Uploaded CSV is empty. Please provide a file with network flow records.")
        st.dataframe(raw_df.head(5), width='stretch')

        # Check required feature schema against trained model feature list
        try:
            _, required_features = load_network_model()
            cleaned_preview = raw_df.copy()
            cleaned_preview.columns = [c.strip() for c in cleaned_preview.columns]
            missing_feats = [f for f in required_features if f not in cleaned_preview.columns]
            if missing_feats:
                st.error(
                    "Uploaded CSV is missing required flow features for the trained model.\n"
                    f"Missing (sample): {missing_feats[:8]}...\n"
                    "Please ensure your CSV matches the CIC-IDS2017/CICFlowMeter schema or use the sample fixture."
                )
                st.stop()
        except FileNotFoundError:
            st.warning("Network model features metadata not found. Schema validation skipped.")

        # Analysis Trigger
        if st.button("🚀 Analyze Network Traffic"):
            with st.spinner("Sanitizing flow values and evaluating IDS signatures..."):
                enriched_df, summary = analyze_network_traffic_df(
                    df=raw_df,
                    source_name=uploaded_file.name,
                    persist_history=True,
                )

            st.success("✅ Network Traffic Analysis Completed Successfully!")

            # Metric Cards
            st.divider()
            st.subheader("📊 Traffic Analytics Summary")
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Total Records", summary["total_records"])
            c2.metric("Benign Flows", summary["benign_records"])
            c3.metric(
                "Detected Attacks",
                summary["attack_records"],
                delta=f"{summary['attack_percentage']:.1f}% attack rate",
                delta_color="inverse" if summary["attack_records"] > 0 else "normal",
            )
            c4.metric("Batch Risk Score", f"{summary['risk_score']}/100")
            c5.metric("Score Severity", summary["risk_severity"])
            st.caption("The unified risk score is a decision-support index derived from model outputs, not a calibrated probability.")

            # Threat Alert
            if summary["attack_records"] > 0:
                st.warning(
                    f"⚠️ **Model predictions:** {summary['attack_records']} of {summary['total_records']} "
                    "flows were classified as attacks. Correlate flagged flows with independent telemetry."
                )
            else:
                st.success(
                    "No flows were classified as attacks in this batch. This model result does not establish that the network is threat-free."
                )

            # Visualizations
            col_chart1, col_chart2 = st.columns(2)

            with col_chart1:
                st.markdown("##### Flow Classification Distribution")
                pie_fig = px.pie(
                    names=["Benign", "Attack"],
                    values=[summary["benign_records"], summary["attack_records"]],
                    color=["Benign", "Attack"],
                    color_discrete_map={"Benign": "#38BDF8", "Attack": "#EF4444"},
                    hole=0.4,
                )
                pie_fig.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="#1C2541",
                    font=dict(color="#FFFFFF"),
                    height=300,
                    margin=dict(l=10, r=10, t=20, b=10),
                )
                st.plotly_chart(pie_fig, width='stretch')

            with col_chart2:
                st.markdown("##### Flow Risk Stratification")
                bar_fig = px.bar(
                    x=["Low Risk", "Medium Risk", "High Risk"],
                    y=[summary["low_risk_flows"], summary["medium_risk_flows"], summary["high_risk_flows"]],
                    color=["Low Risk", "Medium Risk", "High Risk"],
                    color_discrete_map={"Low Risk": "#10B981", "Medium Risk": "#F59E0B", "High Risk": "#EF4444"},
                    text_auto=True,
                )
                bar_fig.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="#1C2541",
                    plot_bgcolor="#0B132B",
                    font=dict(color="#FFFFFF"),
                    height=300,
                    margin=dict(l=10, r=10, t=20, b=10),
                    yaxis_title="Flow Count",
                    showlegend=False,
                )
                st.plotly_chart(bar_fig, width='stretch')

            # Enriched Results Table
            st.divider()
            st.subheader("🔍 Classified Network Flows (Enriched Preview)")

            severity_options = ["Low", "Medium", "High", "Critical"]
            selected_severities = st.multiselect(
                "Filter by risk severity",
                severity_options,
                default=severity_options,
                key="network_risk_filter",
            )
            prediction_options = sorted(enriched_df["Predicted_Class"].dropna().unique().tolist())
            selected_predictions = st.multiselect(
                "Filter by prediction",
                prediction_options,
                default=prediction_options,
                key="network_prediction_filter",
            )
            filtered_df = enriched_df[
                enriched_df["Risk_Severity"].isin(selected_severities)
                & enriched_df["Predicted_Class"].isin(selected_predictions)
            ]

            # Select key summary columns for clean viewing
            key_cols = [
                col for col in [
                    "Destination Port", "Flow Duration", "Total Fwd Packets",
                    "Total Backward Packets", "Flow Bytes/s", "Flow Packets/s",
                    "Predicted_Class", "Attack_Probability", "Risk_Score",
                    "Risk_Severity", "Risk_Level"
                ] if col in enriched_df.columns
            ]

            if filtered_df.empty:
                st.info("No flows match the selected prediction and severity filters.")
            else:
                st.dataframe(filtered_df[key_cols].head(50), width='stretch')

            # CSV Download Button
            csv_bytes = generate_csv_bytes(filtered_df)
            st.download_button(
                label="📥 Download Filtered Enriched Prediction CSV",
                data=csv_bytes,
                file_name=f"cybermorph_nids_results_{uploaded_file.name}",
                mime="text/csv",
                
            )

    except ValueError as ve:
        st.error(f"❌ Schema Validation Error: {ve}")
    except Exception as exc:
        st.error(f"❌ Analysis Pipeline Error: {exc}")
else:
    st.info("💡 **Ready for Inspection:** Upload a CIC-IDS2017 network traffic CSV file or use the sample download button above.")

st.divider()
st.caption(
    "⚠️ **Operational Notice:** Predictions reflect machine learning anomaly models trained on the CIC-IDS2017 benchmark. "
    "A predicted attack should be treated as an alert requiring analyst correlation, not a definitive forensic verdict."
)
