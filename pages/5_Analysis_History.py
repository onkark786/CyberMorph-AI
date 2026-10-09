from __future__ import annotations

import pandas as pd
import streamlit as st

from src.config import APP_TITLE
from src.database import (
    clear_all_history,
    delete_analysis_record,
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

# Fetch filtered records
try:
    history_records = get_analysis_history(
        limit=100,
        analysis_type=None if type_filter == "All" else type_filter.lower(),
        risk_filter=None if risk_filter == "All" else risk_filter.lower(),
        search_query=search_term,
    )
except Exception as exc:
    st.error(f"Unable to load analysis history: {exc}")
    history_records = []

st.caption(f"Displaying **{len(history_records)}** recorded security events matching the current criteria.")

refresh_col, count_col = st.columns([1, 3])
with refresh_col:
    if st.button("🔄 Refresh History", use_container_width=True):
        st.rerun()
with count_col:
    total_count = len(get_analysis_history(limit=10000))
    st.metric("Total Records in Database", total_count)

if history_records:
    col_exp, col_purge = st.columns([2, 1])
    with col_exp:
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
            use_container_width=True,
        )

    with col_purge:
        with st.expander("🗑️ Clear History"):
            st.warning("This action permanently deletes all records from the SQLite history table.")
            confirm = st.checkbox("I confirm I want to erase all history.")
            if st.button("Purge All Records", disabled=not confirm, use_container_width=True):
                deleted_cnt = clear_all_history()
                st.success(f"Purged {deleted_cnt} history records.")
                st.rerun()

    st.divider()
    st.dataframe(
        pd.DataFrame(history_records)[[
            "id", "timestamp", "analysis_type", "input_summary",
            "predicted_class", "risk_level", "model_name", "result_summary"
        ]],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No matching analysis records were found for the current filters. Run a phishing check or upload a network flow CSV to create history entries.")
