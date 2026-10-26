from __future__ import annotations

from datetime import datetime, timezone

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.config import APP_TITLE
from src.database import (
    get_analysis_history,
    get_overview_stats,
    get_security_alert_counts,
    get_security_alerts,
)
from src.network_ids import is_network_model_trained
from src.phishing import is_model_trained as is_phishing_model_trained
from src.ui_theme import (
    apply_custom_theme,
    render_brand_sidebar,
    render_page_header,
    render_status_pill,
)

st.set_page_config(
    page_title=f"{APP_TITLE} | Security Overview",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_custom_theme()
render_brand_sidebar()

now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
render_page_header(
    title="CyberMorph AI",
    subtitle="Explainable AI-Powered Cyber Threat Detection • SOC telemetry and threat intelligence overview",
    icon="🛡️",
)

stats = get_overview_stats()
phishing_ready = is_phishing_model_trained()
network_ready = is_network_model_trained()

st.markdown(
    f"""
    <div class="cyber-alert" style="margin-bottom: 1rem;">
        <strong>Security operations snapshot</strong>
        <span style="color: #94a3b8; margin-left: 0.6rem;">Last refresh: {now_str}</span>
    </div>
    """,
    unsafe_allow_html=True,
)

status_col1, status_col2 = st.columns(2)
with status_col1:
    render_status_pill(
        "Phishing Model",
        phishing_ready,
        "Active / UCI benchmark",
        "Not trained",
    )
with status_col2:
    render_status_pill(
        "Network IDS",
        network_ready,
        "Active / CIC-IDS2017",
        "Not trained",
    )

with st.container(border=True):
    st.subheader("Threat overview", icon=":material/query_stats:")
    metric_rows = (
        (
            ("Total analyses", int(stats.get("total_analyses", 0)), "Stored security evaluations in the local SQLite database."),
            ("URLs analyzed", int(stats.get("total_phishing", 0)), "Phishing checks recorded in the database."),
            ("Phishing predictions", int(stats.get("malicious_phishing", 0)), "URLs classified as phishing by the model."),
        ),
        (
            ("Network flows analyzed", int(stats.get("total_network_flows", 0)), "Flow records processed across uploaded CSV batches."),
            ("Predicted attacks", int(stats.get("attack_network_flows", 0)), "Network flows classified as attacks by the model."),
            ("High-risk incidents", int(stats.get("high_risk_count", 0)), "High-risk records currently stored in the audit log."),
        ),
    )
    for row in metric_rows:
        metric_cols = st.columns(3)
        for col, (label, value, help_text) in zip(metric_cols, row):
            col.metric(label, value, help=help_text)

with st.container(border=True):
    st.subheader("Quick actions", icon=":material/bolt:")
    action_rows = (
        (
            ("Analyze a URL", "pages/1_Phishing_Detection.py"),
            ("Inspect network traffic", "pages/2_Network_Intrusion.py"),
            ("Model performance", "pages/4_Model_Evaluation.py"),
        ),
        (
            ("Analysis history", "pages/5_Analysis_History.py"),
            ("Generate a report", "pages/6_Reports.py"),
            ("Security alerts", "pages/8_Security_Alerts.py"),
        ),
    )
    for row in action_rows:
        action_cols = st.columns(3)
        for col, (label, page_path) in zip(action_cols, row):
            with col:
                if st.button(label):
                    st.switch_page(page_path)

with st.container(border=True):
    st.subheader("Security alert center", icon=":material/notification_important:")
    try:
        alert_counts = get_security_alert_counts()
        alert_metric_rows = (
            (
                ("Open alerts", alert_counts.get("open", 0)),
                ("Acknowledged", alert_counts.get("acknowledged", 0)),
                ("Critical", alert_counts.get("critical", 0)),
            ),
            (
                ("High", alert_counts.get("high", 0)),
                ("Average risk index", f"{stats.get('average_risk_score', 0.0):.1f}/100"),
                ("Scored analyses", stats.get("scored_analyses", 0)),
            ),
        )
        for row in alert_metric_rows:
            alert_cols = st.columns(3)
            for col, (label, value) in zip(alert_cols, row):
                col.metric(label, value)

        active_alerts = get_security_alerts(limit=5, status="OPEN")
        if active_alerts:
            st.dataframe(
                [{
                    "Created (UTC)": alert["created_at"],
                    "Type": alert["analysis_type"].title(),
                    "Target": alert["target"],
                    "Model prediction": alert["predicted_class"],
                    "Risk score": alert["risk_score"],
                    "Severity": alert["severity"],
                } for alert in active_alerts],
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("No open alerts. New medium-or-higher scored analyses appear here.")
    except Exception as exc:
        st.error(f"Unable to load the Security Alert Center: {exc}")

chart_cols = st.columns(3)
with chart_cols[0]:
    st.markdown("<div class='section-header'>Phishing distribution</div>", unsafe_allow_html=True)
    legit = int(stats.get("legitimate_phishing", 0))
    phish = int(stats.get("malicious_phishing", 0))
    if legit == 0 and phish == 0:
        st.info("No phishing entries have been recorded yet.")
    else:
        phish_fig = px.pie(
            names=["Legitimate", "Phishing"],
            values=[legit, phish],
            color=["Legitimate", "Phishing"],
            color_discrete_map={"Legitimate": "#34d399", "Phishing": "#f87171"},
            hole=0.42,
        )
        phish_fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0f172a",
            plot_bgcolor="#0f172a",
            font=dict(color="#e2e8f0"),
            height=280,
            margin=dict(l=10, r=10, t=10, b=10),
        )
        st.plotly_chart(phish_fig, width='stretch')

with chart_cols[1]:
    st.markdown("<div class='section-header'>Network flow status</div>", unsafe_allow_html=True)
    net_benign = int(stats.get("benign_network_flows", 0))
    net_attack = int(stats.get("attack_network_flows", 0))
    if net_benign == 0 and net_attack == 0:
        st.info("No network analysis records are available yet.")
    else:
        net_fig = px.pie(
            names=["Benign", "Attack"],
            values=[net_benign, net_attack],
            color=["Benign", "Attack"],
            color_discrete_map={"Benign": "#60a5fa", "Attack": "#f87171"},
            hole=0.42,
        )
        net_fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0f172a",
            plot_bgcolor="#0f172a",
            font=dict(color="#e2e8f0"),
            height=280,
            margin=dict(l=10, r=10, t=10, b=10),
        )
        st.plotly_chart(net_fig, width='stretch')

with chart_cols[2]:
    st.markdown("<div class='section-header'>Risk severity</div>", unsafe_allow_html=True)
    high_count = int(stats.get("high_risk_count", 0))
    medium_count = int(stats.get("medium_risk_count", 0))
    low_count = int(stats.get("low_risk_count", 0))
    if high_count == 0 and medium_count == 0 and low_count == 0:
        st.info("No severity records are available yet.")
    else:
        risk_fig = go.Figure(
            go.Bar(
                x=["High", "Medium", "Low"],
                y=[high_count, medium_count, low_count],
                marker=dict(color=["#f87171", "#fbbf24", "#34d399"]),
                text=[high_count, medium_count, low_count],
                textposition="auto",
                hovertemplate="%{x}: %{y}<extra></extra>",
            )
        )
        risk_fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0f172a",
            plot_bgcolor="#0f172a",
            font=dict(color="#e2e8f0"),
            height=280,
            margin=dict(l=10, r=10, t=10, b=10),
            yaxis_title="Incident Count",
        )
        st.plotly_chart(risk_fig, width='stretch')

with st.container(border=True):
    st.subheader("Recent activity", icon=":material/history:")
# Lightweight recent activity inspector with client-side filters
    recent_type = st.selectbox("Recent type", ["All", "Phishing", "Network"], index=0)
    recent_risk = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"], index=0)
    recent_start = st.date_input("From", value=None)
    recent_end = st.date_input("To", value=None)

    recent_history = get_analysis_history(limit=200)

    def _filter_recent(records: list[dict]):
        import pandas as _pd
        if not records:
            return []
        df = _pd.DataFrame(records)
        if recent_type != "All":
            df = df[df["analysis_type"].str.lower() == recent_type.lower()]
        if recent_risk != "All":
            df = df[df["risk_level"].str.lower() == recent_risk.lower()]
        if recent_start or recent_end:
            df["_ts"] = _pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
            if recent_start:
                df = df[df["_ts"] >= _pd.Timestamp(recent_start, tz="UTC")]
            if recent_end:
                end_exclusive = _pd.Timestamp(recent_end, tz="UTC") + _pd.Timedelta(days=1)
                df = df[df["_ts"] < end_exclusive]
        return df.sort_values(by="timestamp", ascending=False).to_dict(orient="records")

    recent_filtered = _filter_recent(recent_history)
    if recent_filtered:
        table_rows = [{
            "ID": r["id"],
            "Timestamp (UTC)": r["timestamp"],
            "Type": r["analysis_type"].title(),
            "Target": r["input_summary"],
            "Model prediction": r["predicted_class"],
            "Risk": r["risk_level"],
            "Model": r["model_name"],
        } for r in recent_filtered[:12]]
        st.dataframe(table_rows, width="stretch", hide_index=True)

        for r in recent_filtered[:12]:
            with st.expander(f"[{r.get('timestamp')}] {r.get('analysis_type','').title()} — {r.get('input_summary')}"):
                st.write({
                    "Model prediction": r.get("predicted_class"),
                    "Risk assessment": r.get("risk_level"),
                    "Model": r.get("model_name"),
                })
                if r.get("details"):
                    st.markdown("**Stored diagnostics**")
                    st.json(r.get("details"))
                st.caption("Model-generated results are decision-support signals; corroborate them with independent telemetry.")
    else:
        st.info("No recorded analyses match the active filters. Use the Phishing or Network pages to generate analysis records.")
