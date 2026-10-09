from __future__ import annotations

from typing import Any
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def create_confusion_matrix_plot(
    cm: list[list[int]],
    class_names: list[str],
    title: str = "Confusion Matrix",
) -> go.Figure:
    """Create an interactive Plotly heatmap for a confusion matrix."""
    fig = go.Figure(
        data=go.Heatmap(
            z=cm,
            x=[f"Predicted {c}" for c in class_names],
            y=[f"Actual {c}" for c in class_names],
            text=cm,
            texttemplate="%{text}",
            textfont=dict(size=16, color="#FFFFFF"),
            colorscale="Blues",
            showscale=True,
        )
    )
    fig.update_layout(
        title=title,
        template="plotly_dark",
        paper_bgcolor="#1C2541",
        plot_bgcolor="#0B132B",
        font=dict(color="#FFFFFF"),
        xaxis_title="Predicted Class",
        yaxis_title="True Class",
        height=380,
        margin=dict(l=20, r=20, t=50, b=20),
    )
    return fig


def create_model_comparison_plot(
    models_dict: dict[str, dict[str, Any]],
    title: str = "Model Performance Comparison (Held-out Test Partition)",
) -> go.Figure:
    """Generate a grouped bar chart comparing Accuracy, Precision, Recall, and F1 across trained models."""
    records = []
    for model_name, metrics in models_dict.items():
        records.append({
            "Model": model_name,
            "Accuracy": metrics.get("accuracy", 0.0),
            "Precision": metrics.get("precision", 0.0),
            "Recall": metrics.get("recall", 0.0),
            "F1-Score": metrics.get("f1_score", 0.0),
        })

    df = pd.DataFrame(records)
    melted = df.melt(id_vars=["Model"], var_name="Metric", value_name="Score")

    fig = px.bar(
        melted,
        x="Model",
        y="Score",
        color="Metric",
        barmode="group",
        text_auto=".3f",
        title=title,
        color_discrete_sequence=["#00F2FE", "#4FACFE", "#38BDF8", "#818CF8"],
    )
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#1C2541",
        plot_bgcolor="#0B132B",
        font=dict(color="#FFFFFF"),
        yaxis=dict(range=[0.0, 1.05], title="Score (0.0 - 1.0)"),
        height=400,
        margin=dict(l=20, r=20, t=50, b=20),
    )
    return fig


def format_classification_report_table(report_dict: dict[str, Any]) -> pd.DataFrame:
    """Convert scikit-learn classification_report dict into a clean display DataFrame."""
    rows = []
    for key, val in report_dict.items():
        if isinstance(val, dict):
            rows.append({
                "Class / Metric": key,
                "Precision": round(val.get("precision", 0.0), 4),
                "Recall": round(val.get("recall", 0.0), 4),
                "F1-Score": round(val.get("f1-score", 0.0), 4),
                "Support": int(val.get("support", 0)),
            })
    return pd.DataFrame(rows)
