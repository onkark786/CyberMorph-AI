from __future__ import annotations

import streamlit as st

from src.config import ACADEMIC_TITLE, APP_SUBTITLE, APP_TITLE
from src.ui_theme import apply_custom_theme, render_brand_sidebar, render_page_header

st.set_page_config(
    page_title=f"{APP_TITLE} | About Project",
    page_icon="ℹ️",
    layout="wide",
)

apply_custom_theme()
render_brand_sidebar()

render_page_header(
    title="About CyberMorph AI — Academic Specification",
    subtitle="Final-Year Engineering AI/ML Cybersecurity Project Architecture & Viva Guide.",
    icon="ℹ️",
)

st.markdown(
    f"""
    ### 🎓 Project Identity
    - **Product Name:** {APP_TITLE}
    - **Subtitle:** {APP_SUBTITLE}
    - **Official Academic Title:**
      > *“{ACADEMIC_TITLE}”*
    - **Engineering Discipline:** Artificial Intelligence, Machine Learning, Cybersecurity & Data Analytics
    - **Target Evaluators:** Academic Examiners, Security Analysts, and Students
    """
)

st.divider()

col_col1, col_col2 = st.columns(2)

with col_col1:
    st.subheader("🏛️ Architectural Components")
    st.markdown(
        """
        CyberMorph AI unifies defensive threat intelligence into five coupled modules:
        1. **Security Operations Center (Overview):** Aggregated metrics, incident distributions, and quick actions.
        2. **Phishing URL Detection Engine:** Passive lexical URL parsing mapping to the 30-feature UCI standard.
        3. **Network Intrusion Detection System:** Flow-based packet telemetry classification on the CIC-IDS2017 benchmark.
        4. **Explainable AI (XAI):** Global feature importances and local diagnostic signals preventing black-box opacity.
        5. **Audit Trail & Reporting:** Local SQLite persistence with on-demand CSV and ReportLab PDF compilation.
        """
    )

with col_col2:
    st.subheader("💻 Technology Stack")
    st.markdown(
        """
        - **Programming Language:** Python 3.14 / 3.13 (64-bit)
        - **Frontend & Dashboard:** Streamlit
        - **Machine Learning Core:** Scikit-learn (Random Forest, Decision Tree, Logistic Regression)
        - **Model Persistence:** Joblib & JSON schemas
        - **Data Processing:** Pandas & NumPy
        - **Interactive Visualizations:** Plotly
        - **Database:** SQLite3 (parameterized queries)
        - **Report Generation:** ReportLab
        - **Testing & Quality:** Pytest
        """
    )

st.divider()

st.subheader("📚 Benchmark Datasets & Academic Citations")
st.markdown(
    """
    1. **UCI Phishing Websites Dataset:**
       - *Source:* UCI Machine Learning Repository (ID: 327)
       - *Citation:* Mohammad, R. M., Thabtah, F., & McCluskey, L. (2015). Predicting phishing websites based on self-structuring neural network. *Neural Computing and Applications*.
       - *Features:* 30 engineered discrete indicators covering structural, protocol, and lexical website attributes.
    2. **CIC-IDS2017 Intrusion Detection Dataset:**
       - *Source:* Canadian Institute for Cybersecurity (University of New Brunswick)
       - *Citation:* Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. *ICISSP*.
       - *Features:* 80 network flow features extracted by CICFlowMeter representing realistic network behavior.
    """
)

st.divider()

st.subheader("🎙️ Project Viva & Defense Key Takeaways")
with st.expander("Q: Why was Random Forest selected for Phishing Detection?"):
    st.write(
        "Random Forest is an ensemble of decorrelated decision trees using bagging (bootstrap aggregation). "
        "It excels on discrete and non-linear tabular features like the UCI dataset, reduces overfitting compared to single trees, "
        "and provides intrinsic feature importance scores."
    )

with st.expander("Q: How does the application avoid data leakage?"):
    st.write(
        "Preprocessing transformations (such as scalers and imputation) and model evaluations are strictly isolated. "
        "The train/test split is performed using stratified sampling before model fitting, ensuring held-out test data is never observed during training."
    )

with st.expander("Q: How is local explainability implemented?"):
    st.write(
        "CyberMorph AI evaluates observed feature vectors against legitimate baseline distributions, calculating which signals increased "
        "the phishing probability (e.g., presence of an IP address or URL shortener) versus signals that reinforced legitimacy."
    )

with st.expander("Q: Why does the system perform passive lexical extraction rather than crawling URLs?"):
    st.write(
        "Safety and defensive containment: Automatically visiting untrusted or adversarial URLs exposes the analyst machine to "
        "drive-by downloads, malicious redirects, or credential harvesting triggers. Passive lexical inspection extracts threat indicators safely."
    )
