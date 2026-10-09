from __future__ import annotations

from typing import Any, Optional
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from src.url_features import get_feature_descriptions


def get_global_feature_importances(model, feature_names: list[str], top_n: int = 15) -> pd.DataFrame:
    """
    Extract global feature importance from a trained scikit-learn model.
    Supports Tree-based models (RandomForest, DecisionTree) and linear models (LogisticRegression).
    """
    importances = None

    # Pipeline unwrapping
    underlying_model = model
    if hasattr(model, "named_steps") and "model" in model.named_steps:
        underlying_model = model.named_steps["model"]

    # Tree models
    if hasattr(underlying_model, "feature_importances_"):
        importances = underlying_model.feature_importances_
    # Linear models
    elif hasattr(underlying_model, "coef_"):
        # Absolute mean of coefficients across classes
        coefs = underlying_model.coef_
        importances = np.mean(np.abs(coefs), axis=0) if coefs.ndim > 1 else np.abs(coefs[0])

    if importances is None:
        # Fallback uniform
        importances = np.ones(len(feature_names)) / len(feature_names)

    # Normalize to sum 1.0
    total = np.sum(importances)
    normalized = importances / total if total > 0 else importances

    df = pd.DataFrame({
        "Feature": feature_names,
        "Importance": normalized,
    }).sort_values(by="Importance", ascending=False).reset_index(drop=True)

    return df.head(top_n)


def create_feature_importance_plot(
    importance_df: pd.DataFrame,
    title: str = "Top Predictive Features (Global Model Importance)",
) -> go.Figure:
    """Create a styled dark-themed Plotly horizontal bar chart of feature importances."""
    fig = px.bar(
        importance_df.sort_values(by="Importance", ascending=True),
        x="Importance",
        y="Feature",
        orientation="h",
        text_auto=".3f",
        title=title,
        color="Importance",
        color_continuous_scale="Viridis",
    )
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#1C2541",
        plot_bgcolor="#0B132B",
        font=dict(color="#FFFFFF"),
        xaxis_title="Relative Feature Importance Weight",
        yaxis_title="Feature Name",
        height=450,
        margin=dict(l=20, r=20, t=50, b=20),
        coloraxis_showscale=False,
    )
    fig.update_traces(
        textposition="outside",
        cliponaxis=False,
    )
    return fig


def explain_single_url_prediction(
    extracted_features: dict[str, int],
    predicted_label: str,
    top_n: int = 8,
) -> pd.DataFrame:
    """
    Generate an interpretable local explanation for an individual URL prediction.
    Compares extracted values with legitimate baseline values.
    """
    descriptions = get_feature_descriptions()
    explanations = []

    for feat_name, val in extracted_features.items():
        desc_info = descriptions.get(feat_name, {
            "name": feat_name.replace("_", " ").title(),
            "description": f"Lexical signal for {feat_name}",
            "benign_value": 1,
            "phishing_value": -1,
        })

        is_suspicious = (val == desc_info.get("phishing_value", -1))
        impact = "Increases Phishing Risk" if is_suspicious else "Supports Legitimate Classification"

        explanations.append({
            "Signal Name": desc_info["name"],
            "Observed Value": val,
            "Status": "Suspicious" if is_suspicious else "Normal",
            "Impact on Prediction": impact,
            "Context": desc_info["description"],
            "RiskScore": 1.0 if is_suspicious else -0.5,
        })

    df = pd.DataFrame(explanations)
    # Sort suspicious features to the top
    df = df.sort_values(by="RiskScore", ascending=False).reset_index(drop=True)
    return df.head(top_n)


def create_local_explanation_plot(
    explanation_df: pd.DataFrame,
    title: str = "Local Risk Signals for Analyzed URL",
) -> go.Figure:
    """Create a Plotly bar chart indicating which local signals contributed to or mitigated risk."""
    df = explanation_df.copy()
    colors = ["#EF4444" if s == "Suspicious" else "#10B981" for s in df["Status"]]

    fig = go.Figure(
        go.Bar(
            x=df["RiskScore"],
            y=df["Signal Name"],
            orientation="h",
            marker=dict(color=colors),
            text=df["Status"],
            textposition="auto",
        )
    )
    fig.update_layout(
        title=title,
        template="plotly_dark",
        paper_bgcolor="#1C2541",
        plot_bgcolor="#0B132B",
        font=dict(color="#FFFFFF"),
        xaxis_title="Relative Risk Direction (- supports safe, + supports phishing)",
        yaxis_title="Evaluated Signal",
        height=380,
        margin=dict(l=20, r=20, t=50, b=20),
    )
    return fig
