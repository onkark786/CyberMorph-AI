from __future__ import annotations

import streamlit as st

from src.config import APP_TITLE
from src.metrics import (
    create_confusion_matrix_plot,
    create_model_comparison_plot,
    format_classification_report_table,
)
from src.network_ids import get_network_metadata, is_network_model_trained
from src.phishing import get_phishing_metadata, is_model_trained as is_phishing_model_trained
from src.ui_theme import apply_custom_theme, render_brand_sidebar, render_page_header

st.set_page_config(
    page_title=f"{APP_TITLE} | Model Evaluation",
    page_icon="📊",
    layout="wide",
)

apply_custom_theme()
render_brand_sidebar()

render_page_header(
    title="Model Evaluation & Rigorous Benchmark Validation",
    subtitle="Empirical performance metrics measured strictly on held-out test partitions (No data leakage).",
    icon="📊",
)

tab_phish, tab_net, tab_comp = st.tabs([
    "🎣 Phishing Detection Evaluation",
    "🌐 Network IDS Evaluation",
    "⚖️ Cross-Algorithm Comparison",
])

with tab_phish:
    st.subheader("UCI Phishing Websites Benchmark Evaluation")
    if not is_phishing_model_trained():
        st.warning("Phishing model is not trained yet. Run `python scripts/train_phishing_model.py`.")
    else:
        p_meta = get_phishing_metadata() or {}
        p_metrics = p_meta.get("metrics", {})

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Champion Architecture", p_meta.get("selected_model", "Random Forest"))
        c2.metric("Held-out Test Accuracy", f"{p_metrics.get('accuracy', 0.0):.2%}")
        c3.metric("Phishing Class Recall", f"{p_metrics.get('recall', 0.0):.2%}")
        c4.metric("Phishing Class F1-Score", f"{p_metrics.get('f1_score', 0.0):.2%}")

        st.divider()

        col_cm, col_report = st.columns(2)
        with col_cm:
            st.markdown("##### Interactive Confusion Matrix (Held-out Test Set)")
            cm_data = p_metrics.get("confusion_matrix")
            if cm_data:
                fig_cm = create_confusion_matrix_plot(
                    cm_data,
                    class_names=["Phishing", "Legitimate"],
                    title="Phishing Confusion Matrix",
                )
                st.plotly_chart(fig_cm, width='stretch')

        with col_report:
            st.markdown("##### Detailed Classification Report")
            rep_data = p_metrics.get("classification_report")
            if rep_data:
                rep_df = format_classification_report_table(rep_data)
                st.dataframe(rep_df, width='stretch')

            st.markdown(
                f"""
                - **Training Partition:** {p_meta.get('train_samples', 'N/A')} samples (75%)
                - **Held-out Test Partition:** {p_meta.get('test_samples', 'N/A')} samples (25%)
                - **Evaluation Methodology:** Stratified split with reproducible seed (`random_state=42`).
                """
            )

        st.info(
            "💡 **Understanding Errors in Phishing Detection:**\n\n"
            "- **False Positive:** A legitimate website incorrectly flagged as phishing (causes user inconvenience).\n"
            "- **False Negative:** A phishing site misclassified as legitimate (**Critical Hazard** — leaves users vulnerable to credential theft)."
        )

with tab_net:
    st.subheader("CIC-IDS2017 Flow Benchmark Evaluation")
    if not is_network_model_trained():
        st.warning("Network IDS model is not trained yet. Run `python scripts/train_network_model.py`.")
    else:
        n_meta = get_network_metadata() or {}
        n_metrics = n_meta.get("metrics", {})

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Champion Architecture", n_meta.get("selected_model", "Logistic Regression"))
        c2.metric("Held-out Test Accuracy", f"{n_metrics.get('accuracy', 0.0):.2%}")
        c3.metric("Attack Class Recall", f"{n_metrics.get('recall', 0.0):.2%}")
        c4.metric("Attack Class F1-Score", f"{n_metrics.get('f1_score', 0.0):.2%}")

        st.divider()

        col_ncm, col_nrep = st.columns(2)
        with col_ncm:
            st.markdown("##### Interactive Confusion Matrix (Held-out Flows)")
            n_cm_data = n_metrics.get("confusion_matrix")
            if n_cm_data:
                fig_ncm = create_confusion_matrix_plot(
                    n_cm_data,
                    class_names=["Benign", "Attack"],
                    title="Network IDS Confusion Matrix",
                )
                st.plotly_chart(fig_ncm, width='stretch')

        with col_nrep:
            st.markdown("##### Detailed Classification Report")
            n_rep_data = n_metrics.get("classification_report")
            if n_rep_data:
                n_rep_df = format_classification_report_table(n_rep_data)
                st.dataframe(n_rep_df, width='stretch')

            st.markdown(
                f"""
                - **Training Partition:** {n_meta.get('train_samples', 'N/A')} flows (75%)
                - **Held-out Test Partition:** {n_meta.get('test_samples', 'N/A')} flows (25%)
                - **Class Distribution:** Benign ({n_meta.get('class_distribution', {}).get('benign', 'N/A')}), "
                f"Attack ({n_meta.get('class_distribution', {}).get('attack', 'N/A')})"
                """
            )

        st.info(
            "💡 **Understanding Errors in Network Intrusion Detection:**\n\n"
            "- **False Positive:** Benign traffic classified as an attack (generates alert fatigue for SOC analysts).\n"
            "- **False Negative:** Malicious intrusion packet passing undetected as benign (**Severe Threat** — allows network penetration)."
        )

with tab_comp:
    st.subheader("Cross-Algorithm Model Selection Comparison")
    st.caption("Empirical head-to-head comparison between Logistic Regression, Decision Trees, and Random Forests.")

    domain_sel = st.selectbox("Select Domain for Comparison:", ["Phishing Detection", "Network Intrusion Detection"])

    meta_target = (
        get_phishing_metadata() if domain_sel == "Phishing Detection" else get_network_metadata()
    )

    if meta_target and "all_models" in meta_target:
        comp_fig = create_model_comparison_plot(
            meta_target["all_models"],
            title=f"Algorithm Benchmark Comparison — {domain_sel}",
        )
        st.plotly_chart(comp_fig, width='stretch')

        st.markdown("##### Benchmark Metrics Summary Table")
        table_rows = []
        for m_name, m_vals in meta_target["all_models"].items():
            table_rows.append({
                "Algorithm": m_name,
                "Accuracy": f"{m_vals.get('accuracy', 0.0):.4f}",
                "Precision": f"{m_vals.get('precision', 0.0):.4f}",
                "Recall": f"{m_vals.get('recall', 0.0):.4f}",
                "F1-Score": f"{m_vals.get('f1_score', 0.0):.4f}",
            })
        st.dataframe(table_rows, width='stretch')
    else:
        st.info("Full multi-model evaluation data will appear once both training pipelines have run.")
