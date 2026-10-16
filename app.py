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

st.markdown("<div class='section-shell'>", unsafe_allow_html=True)
st.markdown("<div class='section-header'>Threat overview</div>", unsafe_allow_html=True)
metric_cols = st.columns(6)
metric_cols[0].metric(
    "Total Analyses",
    int(stats.get("total_analyses", 0)),
    help="Total stored security evaluations in the local SQLite database.",
)
metric_cols[1].metric(
    "URLs Analyzed",
    int(stats.get("total_phishing", 0)),
    help="Total phishing checks recorded in the database.",
)
metric_cols[2].metric(
    "Phishing URLs Detected",
    int(stats.get("malicious_phishing", 0)),
    help="Count of phishing detections flagged by the model.",
)
metric_cols[3].metric(
    "Network Flows Analyzed",
    int(stats.get("total_network_flows", 0)),
    help="Total network flow records processed across uploaded CSV batches.",
)
metric_cols[4].metric(
    "Predicted Attacks",
    int(stats.get("attack_network_flows", 0)),
    help="Estimated attack flows from the trained network model.",
)
metric_cols[5].metric(
    "High-Risk Incidents",
    int(stats.get("high_risk_count", 0)),
    help="High-risk records currently recorded in the audit log.",
)
st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<div class='section-shell'>", unsafe_allow_html=True)
st.markdown("<div class='section-header'>Quick actions</div>", unsafe_allow_html=True)
action_cols = st.columns(6)
with action_cols[0]:
    if st.button("Analyze a URL"):
        st.switch_page("pages/1_Phishing_Detection.py")
with action_cols[1]:
    if st.button("Inspect Network"):
        st.switch_page("pages/2_Network_Intrusion.py")
with action_cols[2]:
    if st.button("Model Performance"):
        st.switch_page("pages/4_Model_Evaluation.py")
with action_cols[3]:
    if st.button("Analysis History"):
        st.switch_page("pages/5_Analysis_History.py")
with action_cols[4]:
    if st.button("Generate Report"):
        st.switch_page("pages/6_Reports.py")
with action_cols[5]:
    if st.button("Security Alerts"):
        st.switch_page("pages/8_Security_Alerts.py")
st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<div class='section-shell'>", unsafe_allow_html=True)
st.markdown("<div class='section-header'>Security alert center</div>", unsafe_allow_html=True)
try:
    alert_counts = get_security_alert_counts()
    alert_cols = st.columns(6)
    alert_cols[0].metric("Open Alerts", alert_counts.get("open", 0))
    alert_cols[1].metric("Acknowledged", alert_counts.get("acknowledged", 0))
    alert_cols[2].metric("Critical", alert_counts.get("critical", 0))
    alert_cols[3].metric("High", alert_counts.get("high", 0))
    alert_cols[4].metric("Average Risk Index", f"{stats.get('average_risk_score', 0.0):.1f}/100")
    alert_cols[5].metric("Scored Analyses", stats.get("scored_analyses", 0))
    active_alerts = get_security_alerts(limit=5, status="OPEN")
    if active_alerts:
        st.dataframe(
            [{
                "Created (UTC)": alert["created_at"],
                "Type": alert["analysis_type"].title(),
                "Target": alert["target"],
                "Prediction": alert["predicted_class"],
                "Risk Score": alert["risk_score"],
                "Severity": alert["severity"],
            } for alert in active_alerts],
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No open alerts. New medium-or-higher scored analyses appear here.")
except Exception as exc:
    st.error(f"Unable to load the Security Alert Center: {exc}")
st.markdown("</div>", unsafe_allow_html=True)

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

st.markdown("<div class='section-shell'>", unsafe_allow_html=True)
st.markdown("<div class='section-header'>Recent activity</div>", unsafe_allow_html=True)
# Lightweight recent activity inspector with client-side filters
recent_type = st.selectbox("Recent Type:", ["All", "Phishing", "Network"], index=0)
recent_risk = st.selectbox("Severity:", ["All", "High", "Medium", "Low"], index=0)
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
    try:
        df["_ts"] = _pd.to_datetime(df["timestamp"], errors="coerce")
        if recent_start:
            df = df[df["_ts"] >= _pd.to_datetime(recent_start)]
        if recent_end:
            df = df[df["_ts"] <= _pd.to_datetime(recent_end) + _pd.Timedelta(days=1)]
    except Exception:
        pass
    return df.sort_values(by="timestamp", ascending=False).to_dict(orient="records")

recent_filtered = _filter_recent(recent_history)
if recent_filtered:
    table_rows = [{
        "ID": r["id"],
        "Timestamp": r["timestamp"],
        "Type": r["analysis_type"].upper(),
        "Summary": r["input_summary"],
        "Prediction": r["predicted_class"],
        "Risk": r["risk_level"],
        "Model": r["model_name"],
    } for r in recent_filtered[:12]]
    st.dataframe(table_rows, width='stretch', hide_index=True)

    # Provide compact detail expanders for analyst review
    for r in recent_filtered[:12]:
        with st.expander(f"[{r.get('timestamp')}] {r.get('analysis_type','').upper()} — {r.get('input_summary')}"):
            st.write({
                "Prediction": r.get("predicted_class"),
                "Risk": r.get("risk_level"),
                "Model": r.get("model_name"),
            })
            if r.get("details"):
                st.markdown("**Diagnostics**")
                st.json(r.get("details"))
            # navigation hint (no server launch)
            st.caption("Use the Analysis History page to view full audit trails and download records.")
else:
    st.info("No recorded analyses match the active filters. Use the Phishing or Network pages to generate analysis records.")

st.markdown("</div>", unsafe_allow_html=True)
