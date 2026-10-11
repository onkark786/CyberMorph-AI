from __future__ import annotations

import streamlit as st

from src.config import APP_TITLE
from src.explainability import (
    create_feature_importance_plot,
    create_local_explanation_plot,
    explain_single_url_prediction,
    get_global_feature_importances,
)
from src.network_ids import is_network_model_trained, load_network_model
from src.phishing import (
    is_model_trained as is_phishing_model_trained,
    load_phishing_model,
    predict_url,
)
from src.ui_theme import apply_custom_theme, render_brand_sidebar, render_page_header
from src.url_features import get_feature_descriptions

st.set_page_config(
    page_title=f"{APP_TITLE} | Explainable AI (XAI)",
    page_icon="💡",
    layout="wide",
)

apply_custom_theme()
render_brand_sidebar()

render_page_header(
    title="Explainable AI (XAI) & Interpretability Center",
    subtitle="Deconstructing model decision boundaries into transparent, human-auditable security rationales.",
    icon="💡",
)

st.markdown(
    """
    > [!NOTE]
    > **Why Explainability Matters in Cybersecurity:**
    > Machine learning models operating as opaque 'black boxes' can misclassify zero-day variations or exhibit biased shortcuts.
    > CyberMorph AI applies dual-level interpretability: **Global Interpretability** (which signals the model relies on overall)
    > and **Local Interpretability** (why a specific URL or packet was flagged).
    """
)

tab_global, tab_local, tab_academic = st.tabs([
    "🌐 Global Feature Importances",
    "🎯 Local Decision Inspector",
    "📚 XAI Methodology & Caveats",
])

with tab_global:
    st.subheader("Global Model Feature Rankings")
    st.caption("Measures which input dimensions possess the highest explanatory power across entire training distributions.")

    model_choice = st.radio(
        "Select Security Model Domain:",
        ["Phishing Detection (UCI Random Forest)", "Network Intrusion Detection (CIC-IDS2017)"],
        horizontal=True,
    )

    if "Phishing" in model_choice:
        if not is_phishing_model_trained():
            st.warning("Phishing model is not trained yet.")
        else:
            model, feature_names = load_phishing_model()
            top_k = st.slider("Select Top Features to Display:", min_value=5, max_value=30, value=15)
            imp_df = get_global_feature_importances(model, feature_names, top_n=top_k)

            fig = create_feature_importance_plot(
                imp_df,
                title="Global Feature Importance — Phishing Detection Pipeline",
            )
            st.plotly_chart(fig, width='stretch')

            with st.expander("📋 Tabular Feature Importance Weights"):
                st.dataframe(imp_df, use_container_width=True)
    else:
        if not is_network_model_trained():
            st.warning("Network IDS model is not trained yet.")
        else:
            model, feature_names = load_network_model()
            top_k = st.slider("Select Top Features to Display:", min_value=5, max_value=25, value=15)
            imp_df = get_global_feature_importances(model, feature_names, top_n=top_k)

            fig = create_feature_importance_plot(
                imp_df,
                title="Global Feature Importance — Network Intrusion Detection Pipeline",
            )
            st.plotly_chart(fig, width='stretch')

            with st.expander("📋 Tabular Feature Importance Weights"):
                st.dataframe(imp_df, use_container_width=True)

with tab_local:
    st.subheader("Local Instance Explanation (Targeted URL Drilldown)")
    st.caption("Inspect how specific feature deviations shift a single prediction toward or away from high threat severity.")

    test_url = st.text_input(
        "Enter Sample URL to Explain:",
        value="http://192.168.1.55/update-security/paypal-login.php",
    )

    if st.button("Generate Local Explanations"):
        if not is_phishing_model_trained():
            st.error("Phishing model required for local URL explanation.")
        else:
            res = predict_url(test_url)
            st.markdown(f"**Predicted Verdict:** `{res['predicted_label'].upper()}` with **{res['confidence']:.1%}** confidence.")

            exp_df = explain_single_url_prediction(
                res["extracted_features"],
                res["predicted_label"],
                top_n=10,
            )

            fig_local = create_local_explanation_plot(
                exp_df,
                title=f"Instance Explanation for {res['url']}",
            )
            st.plotly_chart(fig_local, use_container_width=True)

            st.markdown("##### Feature Explanations")
            st.dataframe(exp_df[["Signal Name", "Observed Value", "Status", "Impact on Prediction", "Context"]], use_container_width=True)

with tab_academic:
    st.subheader("Academic Principles & Interpretability Limitations")
    st.markdown(
        """
        ### Principles of Responsible Cyber XAI
        1. **Correlation vs. Causation:** High feature importance indicates statistical correlation with malicious samples in historical benchmarks. It does not prove intentional malicious intent on its own.
        2. **Evasion Resistance:** Adversaries who inspect model explanations can deliberately craft adversarial examples (e.g., shortening URL length or spoofing standard ports) to evade simple classifiers.
        3. **Auditing Standard:** Every security alert surfaced by CyberMorph AI retains an audit log in SQLite containing full diagnostic signals so analysts can cross-check determinations.
        """
    )
