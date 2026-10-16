from __future__ import annotations

import streamlit as st

from src.config import APP_TITLE
from src.database import (
    get_security_alert_counts,
    get_security_alerts,
    update_security_alert_status,
)
from src.risk_scoring import DEFAULT_RISK_BANDS
from src.ui_theme import apply_custom_theme, render_brand_sidebar, render_page_header

st.set_page_config(
    page_title=f"{APP_TITLE} | Security Alerts",
    page_icon="🚨",
    layout="wide",
)

apply_custom_theme()
render_brand_sidebar()
render_page_header(
    title="Security Alert Center",
    subtitle="Review model-derived risk alerts, inspect evidence, and track analyst response.",
    icon="🚨",
)

st.caption(
    "Risk score is a 0–100 decision-support index, not a calibrated probability. "
    f"Bands: Low 0–{DEFAULT_RISK_BANDS.low_max}, "
    f"Medium {DEFAULT_RISK_BANDS.low_max + 1}–{DEFAULT_RISK_BANDS.medium_max}, "
    f"High {DEFAULT_RISK_BANDS.medium_max + 1}–{DEFAULT_RISK_BANDS.high_max}, "
    f"Critical {DEFAULT_RISK_BANDS.high_max + 1}–100. Low-band analyses remain in history but do not create alerts."
)

try:
    counts = get_security_alert_counts()
except Exception as exc:
    st.error(f"Unable to read alert summary from SQLite: {exc}")
    counts = {"total": 0, "open": 0, "acknowledged": 0, "resolved": 0, "critical": 0, "high": 0, "medium": 0}

count_cols = st.columns(5)
count_cols[0].metric("Alerts", counts.get("total", 0))
count_cols[1].metric("Open", counts.get("open", 0))
count_cols[2].metric("Acknowledged", counts.get("acknowledged", 0))
count_cols[3].metric("Critical", counts.get("critical", 0))
count_cols[4].metric("Resolved", counts.get("resolved", 0))

search_col, severity_col, type_col, status_col = st.columns([2, 1, 1, 1])
with search_col:
    search_query = st.text_input("Search alerts", placeholder="Target, prediction, evidence, recommendation")
with severity_col:
    severity_filter = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"])
with type_col:
    type_filter = st.selectbox("Analysis type", ["All", "Phishing", "Network"])
with status_col:
    status_filter = st.selectbox("Status", ["All", "OPEN", "ACKNOWLEDGED", "RESOLVED"])

try:
    alerts = get_security_alerts(
        limit=500,
        search_query=search_query,
        severity=severity_filter,
        analysis_type=type_filter,
        status=status_filter,
    )
except Exception as exc:
    st.error(f"Unable to load security alerts: {exc}")
    alerts = []

st.caption(f"Showing {len(alerts)} matching alert(s). Times are stored in UTC.")
if not alerts:
    st.info("No security alerts match these filters. New alerts are created for medium, high, and critical risk scores.")

for alert in alerts:
    title = (
        f"{alert['severity']} · {alert['analysis_type'].title()} · "
        f"{alert['target']} · {alert['risk_score']}/100 · {alert['status'].replace('_', ' ').title()}"
    )
    with st.expander(title):
        detail_cols = st.columns(3)
        detail_cols[0].write(f"**Created:** {alert['created_at']}")
        detail_cols[1].write(f"**Prediction:** {alert['predicted_class']}")
        detail_cols[2].write(f"**Updated:** {alert['updated_at']}")
        if alert.get("acknowledged_at"):
            st.caption(f"Acknowledged: {alert['acknowledged_at']}")
        if alert.get("resolved_at"):
            st.caption(f"Resolved: {alert['resolved_at']}")

        st.markdown("**Evidence**")
        evidence = alert.get("evidence") or []
        if evidence:
            for item in evidence:
                st.markdown(f"- {item}")
        else:
            st.info("No explanatory evidence was stored for this alert.")
        st.markdown(f"**Defensive recommendation:** {alert['recommendation']}")

        action_cols = st.columns(2)
        if alert["status"] == "OPEN":
            if action_cols[0].button("Acknowledge", key=f"ack_{alert['id']}"):
                try:
                    if update_security_alert_status(alert["id"], "ACKNOWLEDGED"):
                        st.rerun()
                    st.warning("Alert status was not changed.")
                except Exception as exc:
                    st.error(f"Could not acknowledge alert: {exc}")
        if alert["status"] in {"OPEN", "ACKNOWLEDGED"}:
            if action_cols[1].button("Resolve", key=f"resolve_{alert['id']}"):
                try:
                    if update_security_alert_status(alert["id"], "RESOLVED"):
                        st.rerun()
                    st.warning("Alert status was not changed.")
                except Exception as exc:
                    st.error(f"Could not resolve alert: {exc}")
