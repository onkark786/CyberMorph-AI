from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.analysis_digs import create_threat_gauge
from src.config import APP_SUBTITLE, APP_TITLE, PROJECT_ROOT
from src.database import get_analysis_history, get_overview_stats
from src.network_ids import is_network_model_trained
from src.phishing import is_model_trained as is_phishing_model_trained
from src.ui_theme import (
    apply_custom_theme,
    render_analysis_dig_box,
    render_brand_sidebar,
    render_page_header,
)

st.set_page_config(
    page_title=f"{APP_TITLE} | Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_custom_theme()
render_brand_sidebar()

# Visual Hero Banner
banner_path = PROJECT_ROOT / "assets" / "hero_banner.jpg"
if banner_path.exists():
    st.image(str(banner_path), use_container_width=True)

# Page Header
now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
render_page_header(
    title=f"{APP_TITLE} — Security Operations Center",
    subtitle=f"Enterprise-grade cyber threat analytics, machine learning telemetry, and audit trail • System Time: {now_str}",
    icon="🛡️",
)

# Fetch stats from SQLite
stats = get_overview_stats()
phishing_ready = is_phishing_model_trained()
network_ready = is_network_model_trained()

# Model Status Badges & Engine Heartbeat
col_stat1, col_stat2 = st.columns(2)
with col_stat1:
    if phishing_ready:
        st.success("🟢 **Phishing Engine:** Active (Random Forest / UCI Benchmark)")
    else:
        st.warning("🟡 **Phishing Engine:** Untrained (Run training script)")

with col_stat2:
    if network_ready:
        st.success("🟢 **Network IDS Engine:** Active (Logistic Regression / CIC-IDS2017)")
    else:
        st.warning("🟡 **Network IDS Engine:** Untrained (Run training script)")

st.divider()

# High-Level Metric Cards
st.subheader("📊 Key Threat Telemetry")
m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Total Sessions", stats["total_analyses"], help="Total distinct analysis runs recorded in database")
m2.metric("URLs Evaluated", stats["total_phishing"], help="Number of URLs checked for phishing")
m3.metric("Phishing Flagged", stats["malicious_phishing"], delta=f"{stats['malicious_phishing']} threats", delta_color="inverse")
m4.metric("Flows Analyzed", stats["total_network_flows"], help="Total individual network flow packets examined")
m5.metric("Intrusions Detected", stats["attack_network_flows"], delta=f"{stats['attack_network_flows']} attacks", delta_color="inverse")
m6.metric("High-Risk Incidents", stats["high_risk_count"], delta_color="inverse")

st.divider()

# Visual Threat Gauge & Threat Distribution Digs
st.subheader("🎯 Threat Posture & Analysis Digs")
col_gauge, col_pie1, col_pie2 = st.columns([1.1, 1, 1])

# Threat posture percentage calculation
total_items = max(1, stats["total_phishing"] + stats["total_network_flows"])
total_threats = stats["malicious_phishing"] + stats["attack_network_flows"]
threat_ratio = (total_threats / total_items) * 100.0 if total_items > 0 else 0.0

with col_gauge:
    gauge_fig = create_threat_gauge(
        risk_percentage=round(threat_ratio, 1),
        title="Aggregate Threat Posture",
    )
    st.plotly_chart(gauge_fig, use_container_width=True)

with col_pie1:
    st.markdown("##### Phishing vs Legitimate URLs")
    p_legit = stats["legitimate_phishing"]
    p_mal = stats["malicious_phishing"]
    if p_legit == 0 and p_mal == 0:
        st.info("No URL analyses recorded yet.")
    else:
        fig_phish = px.pie(
            names=["Legitimate", "Phishing"],
            values=[p_legit, p_mal],
            color=["Legitimate", "Phishing"],
            color_discrete_map={"Legitimate": "#10B981", "Phishing": "#EF4444"},
            hole=0.5,
        )
        fig_phish.update_layout(
            template="plotly_dark",
            paper_bgcolor="#1C2541",
            font=dict(color="#FFFFFF"),
            height=260,
            margin=dict(l=10, r=10, t=10, b=10),
        )
        st.plotly_chart(fig_phish, use_container_width=True)

with col_pie2:
    st.markdown("##### Benign vs Attack Network Flows")
    net_benign = stats["benign_network_flows"]
    net_attack = stats["attack_network_flows"]
    if net_benign == 0 and net_attack == 0:
        st.info("No network flows uploaded yet.")
    else:
        fig_net = px.pie(
            names=["Benign", "Attack"],
            values=[net_benign, net_attack],
            color=["Benign", "Attack"],
            color_discrete_map={"Benign": "#38BDF8", "Attack": "#F43F5E"},
            hole=0.5,
        )
        fig_net.update_layout(
            template="plotly_dark",
            paper_bgcolor="#1C2541",
            font=dict(color="#FFFFFF"),
            height=260,
            margin=dict(l=10, r=10, t=10, b=10),
        )
        st.plotly_chart(fig_net, use_container_width=True)

# Educational Analysis Dig Callout
render_analysis_dig_box(
    title="Analysis Dig: How to Read the Threat Posture Gauge",
    explanation=(
        "The Threat Posture Gauge synthesizes telemetry across both URL lexical scanning and network flow monitoring. "
        "It expresses the proportion of inspected targets exhibiting confirmed malicious signatures."
    ),
    takeaways=[
        "🟢 0% - 35%: Safe / Benign Baseline — Normal network operations and safe web link distribution.",
        "🟡 35% - 70%: Elevated Risk — Targeted phishing campaigns or suspicious network reconnaissance detected.",
        "🔴 70% - 100%: Critical Incident State — Severe active intrusions or weaponized credential harvesting links.",
    ],
)

st.divider()

# Quick Navigation Actions
st.subheader("⚡ Threat Response Actions")
q1, q2, q3, q4 = st.columns(4)
with q1:
    if st.button("🎣 Inspect a URL", use_container_width=True):
        st.switch_page("pages/1_Phishing_Detection.py")
with q2:
    if st.button("🌐 Analyze Network Flows", use_container_width=True):
        st.switch_page("pages/2_Network_Intrusion.py")
with q3:
    if st.button("💡 Explore Explainable XAI", use_container_width=True):
        st.switch_page("pages/3_Explainable_AI.py")
with q4:
    if st.button("📄 Generate Audit Report", use_container_width=True):
        st.switch_page("pages/6_Reports.py")

st.divider()

# Recent Activity Audit Trail
st.subheader("🕒 Recent Security Analysis Activity")
recent_history = get_analysis_history(limit=8)

if recent_history:
    display_rows = []
    for r in recent_history:
        display_rows.append({
            "ID": r["id"],
            "Timestamp": r["timestamp"],
            "Type": r["analysis_type"].upper(),
            "Target Summary": r["input_summary"],
            "Prediction": r["predicted_class"],
            "Risk Level": r["risk_level"],
            "Model Name": r["model_name"],
        })
    st.dataframe(display_rows, use_container_width=True)
else:
    st.info("No analyses recorded in database yet. Analyze a URL or upload a network CSV to view live entries.")

st.divider()
st.caption(
    "🛡️ **CyberMorph AI** | Explainable Machine Learning Cybersecurity Platform | "
    "Designed for Final-Year Engineering Demonstration & Academic Viva"
)
