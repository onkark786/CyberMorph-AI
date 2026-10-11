from __future__ import annotations

import pandas as pd
import streamlit as st

from src.config import APP_TITLE
from src.database import (
    get_analysis_history,
)
from src.reporting import generate_csv_bytes
from src.ui_theme import apply_custom_theme, render_brand_sidebar, render_page_header

st.set_page_config(
    page_title=f"{APP_TITLE} | Analysis History",
    page_icon="🕒",
    layout="wide",
)

apply_custom_theme()
render_brand_sidebar()

render_page_header(
    title="Security Analysis History & Audit Trail",
    subtitle="Persistent SQLite telemetry log tracking every evaluated URL and network traffic batch.",
    icon="🕒",
)

# Filtering Controls
col_f1, col_f2, col_f3 = st.columns(3)
with col_f1:
    type_filter = st.selectbox("Filter by Analysis Type:", ["All", "Phishing", "Network"])
with col_f2:
    risk_filter = st.selectbox("Filter by Severity Risk:", ["All", "High", "Medium", "Low"])
with col_f3:
    search_term = st.text_input("Search Target or Keyword:", placeholder="e.g. paypal, batch, port")

# Date range filter (client-side only; does not mutate DB)
col_d1, col_d2 = st.columns(2)
with col_d1:
    start_date = st.date_input("Start Date", value=None)
with col_d2:
    end_date = st.date_input("End Date", value=None)

# Fetch filtered records from DB (server-side filters supported by helper)
try:
    history_records = get_analysis_history(
        limit=1000,
        analysis_type=None if type_filter == "All" else type_filter.lower(),
        risk_filter=None if risk_filter == "All" else risk_filter.lower(),
        search_query=search_term,
    )
except Exception as exc:
    st.error(f"Unable to load analysis history: {exc}")
    history_records = []

# Apply client-side date filtering if requested
if history_records and (start_date or end_date):
    try:
        df_hist = pd.DataFrame(history_records)
        df_hist["_parsed_ts"] = pd.to_datetime(df_hist["timestamp"], errors="coerce")
        if start_date:
            df_hist = df_hist[df_hist["_parsed_ts"] >= pd.to_datetime(start_date)]
        if end_date:
            df_hist = df_hist[df_hist["_parsed_ts"] <= pd.to_datetime(end_date) + pd.Timedelta(days=1)]
        history_records = df_hist.drop(columns=["_parsed_ts"]).to_dict(orient="records")
    except Exception:
        # If parsing fails, leave original records and show a gentle warning
        st.warning("Could not apply date filter due to unexpected timestamp format in the DB.")

st.caption(f"Displaying **{len(history_records)}** recorded security events matching the current criteria.")

refresh_col, count_col = st.columns([1, 3])
with refresh_col:
    if st.button("🔄 Refresh History"):
        st.rerun()
with count_col:
    total_count = len(get_analysis_history(limit=10000))
    st.metric("Total Records in Database", total_count)

if history_records:
    history_df = pd.DataFrame(history_records)
    export_cols = [
        "id", "timestamp", "analysis_type", "input_summary",
        "predicted_class", "risk_level", "probability", "model_name", "result_summary"
    ]
    clean_export_df = history_df[[col for col in export_cols if col in history_df.columns]]
    csv_bytes = generate_csv_bytes(clean_export_df)
    st.download_button(
        label="📥 Export Filtered History (CSV)",
        data=csv_bytes,
        file_name="cybermorph_analysis_history.csv",
        mime="text/csv",
    )

    st.divider()
    # Table of recent events
    display_df = history_df[[
        "id", "timestamp", "analysis_type", "input_summary",
        "predicted_class", "risk_level", "model_name", "result_summary"
    ]].copy()
    st.dataframe(display_df, width='stretch', hide_index=True)

    # Detailed per-record view
    st.markdown("---")
    st.subheader("Detailed Incident Views")
    for rec in history_records:
        with st.expander(f"[{rec.get('timestamp')}] {rec.get('analysis_type', '').upper()} — {rec.get('input_summary')} "):
            st.write(rec)
            if rec.get("details"):
                st.markdown("**Stored Diagnostics / Details**")
                st.json(rec.get("details"))
            # download individual record as CSV row
            try:
                single_csv = generate_csv_bytes(pd.DataFrame([rec]))
                st.download_button(
                    label="Download Record (CSV)",
                    data=single_csv,
                    file_name=f"analysis_{rec.get('id')}.csv",
                    mime="text/csv",
                )
            except Exception:
                pass
else:
    st.info("No matching analysis records were found for the current filters. Run a phishing check or upload a network flow CSV to create history entries.")
