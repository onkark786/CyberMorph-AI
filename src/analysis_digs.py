from __future__ import annotations

from typing import Any, Optional
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def create_threat_gauge(
    risk_percentage: float,
    label: str = "Threat Score",
    title: str = "Threat Severity Gauge",
) -> go.Figure:
    """
    Renders a futuristic dark-mode circular dial / gauge meter for threat probability.
    """
    pct = max(0.0, min(100.0, risk_percentage))

    if pct >= 70.0:
        bar_color = "#EF4444"
        level_text = "CRITICAL ALERT"
    elif pct >= 35.0:
        bar_color = "#F59E0B"
        level_text = "ELEVATED RISK"
    else:
        bar_color = "#10B981"
        level_text = "BENIGN / LOW"

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number+delta",
            value=pct,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": f"<b>{title}</b><br><span style='font-size:0.8em;color:{bar_color};'>{level_text}</span>", "font": {"color": "#FFFFFF", "size": 16}},
            number={"suffix": "%", "font": {"color": "#FFFFFF", "size": 36, "family": "Inter, sans-serif"}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#64748B", "tickfont": {"color": "#94A3B8"}},
                "bar": {"color": bar_color, "thickness": 0.3},
                "bgcolor": "#1C2541",
                "borderwidth": 2,
                "bordercolor": "#2A3B5C",
                "steps": [
                    {"range": [0, 35], "color": "rgba(16, 185, 129, 0.15)"},
                    {"range": [35, 70], "color": "rgba(245, 158, 11, 0.15)"},
                    {"range": [70, 100], "color": "rgba(239, 68, 68, 0.15)"},
                ],
                "threshold": {
                    "line": {"color": "#EF4444", "width": 4},
                    "thickness": 0.75,
                    "value": 70,
                },
            },
        )
    )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#1C2541",
        plot_bgcolor="#0B132B",
        font=dict(color="#FFFFFF"),
        height=260,
        margin=dict(l=20, r=20, t=50, b=20),
    )
    return fig


def create_url_threat_radar(features: dict[str, int]) -> go.Figure:
    """
    Renders a 5-pillar Threat Vector Radar Dig examining key deceptive dimensions.
    Scores 0-100 (where 100 = maximum threat indicator).
    """
    # 1. Host Integrity
    host_score = 95 if features.get("having_ip_address", 1) == -1 else 10

    # 2. Domain Hierarchy (subdomains & prefix/suffix)
    sub_val = features.get("having_sub_domain", 1)
    prefix_val = features.get("prefix_suffix", 1)
    domain_score = (80 if sub_val == -1 else (45 if sub_val == 0 else 10)) + (20 if prefix_val == -1 else 0)
    domain_score = min(100, domain_score)

    # 3. Protocol & Encryption
    ssl_val = features.get("sslfinal_state", 1)
    https_token_val = features.get("https_token", 1)
    protocol_score = (85 if ssl_val == -1 else 15) + (15 if https_token_val == -1 else 0)
    protocol_score = min(100, protocol_score)

    # 4. Lexical Concealment (length & shortener)
    len_val = features.get("url_length", 1)
    short_val = features.get("shortining_service", 1)
    lexical_score = (70 if len_val == -1 else (40 if len_val == 0 else 15)) + (30 if short_val == -1 else 0)
    lexical_score = min(100, lexical_score)

    # 5. Redirection & Masking (@ symbol & double slash)
    at_val = features.get("having_at_symbol", 1)
    slash_val = features.get("double_slash_redirecting", 1)
    redirection_score = (60 if at_val == -1 else 10) + (40 if slash_val == -1 else 0)
    redirection_score = min(100, redirection_score)

    categories = [
        "Host / IP Deception",
        "Domain Spoofing",
        "Protocol / SSL Risk",
        "Lexical Obfuscation",
        "Redirection Masking",
    ]
    scores = [host_score, domain_score, protocol_score, lexical_score, redirection_score]

    fig = go.Figure()
    fig.add_trace(
        go.Scatterpolar(
            r=scores + [scores[0]],
            theta=categories + [categories[0]],
            fill="toself",
            fillcolor="rgba(0, 242, 254, 0.25)",
            line=dict(color="#00F2FE", width=2.5),
            marker=dict(color="#4FACFE", size=7),
            name="URL Threat Profile",
        )
    )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#1C2541",
        plot_bgcolor="#0B132B",
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 100], color="#94A3B8", gridcolor="#2A3B5C"),
            angularaxis=dict(color="#FFFFFF", gridcolor="#2A3B5C"),
            bgcolor="#151D33",
        ),
        font=dict(color="#FFFFFF"),
        height=320,
        margin=dict(l=40, r=40, t=30, b=30),
        showlegend=False,
    )
    return fig


def create_flow_scatter_dig(df: pd.DataFrame, max_samples: int = 500) -> go.Figure:
    """
    Renders an interactive 2D Scatter Anomaly Dig comparing Flow Duration vs Flow Packets/s.
    """
    sample = df.head(max_samples).copy()

    # Fallback columns if standard not found
    x_col = "Flow Duration" if "Flow Duration" in sample.columns else sample.columns[1]
    y_col = "Flow Packets/s" if "Flow Packets/s" in sample.columns else sample.columns[2]
    color_col = "Predicted_Class" if "Predicted_Class" in sample.columns else None

    # Handle zeros for log scale visualization
    sample["plot_x"] = pd.to_numeric(sample[x_col], errors="coerce").fillna(0).clip(lower=1)
    sample["plot_y"] = pd.to_numeric(sample[y_col], errors="coerce").fillna(0).clip(lower=0.01)

    fig = px.scatter(
        sample,
        x="plot_x",
        y="plot_y",
        color=color_col,
        color_discrete_map={"BENIGN": "#38BDF8", "ATTACK": "#EF4444"},
        hover_data=[c for c in ["Destination Port", "Risk_Level", "Attack_Probability"] if c in sample.columns],
        log_x=True,
        log_y=True,
        title="<b>Flow Telemetry Anomaly Scatter Dig</b> (Duration vs Packet Rate)",
    )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#1C2541",
        plot_bgcolor="#0B132B",
        font=dict(color="#FFFFFF"),
        xaxis_title=f"{x_col} (Log Scale, µs)",
        yaxis_title=f"{y_col} (Log Scale, pkts/sec)",
        height=350,
        margin=dict(l=20, r=20, t=50, b=20),
    )
    fig.update_traces(marker=dict(size=8, opacity=0.8, line=dict(width=0.5, color="#FFFFFF")))
    return fig


def create_port_attack_distribution_dig(df: pd.DataFrame) -> go.Figure:
    """
    Renders Port Clustering Dig showing where suspicious flows concentrate.
    """
    if "Destination Port" not in df.columns:
        return go.Figure()

    port_counts = df.groupby(["Destination Port", "Predicted_Class"]).size().reset_index(name="Count")
    # Top 12 ports by total volume
    top_ports = df["Destination Port"].value_counts().head(12).index.tolist()
    filtered = port_counts[port_counts["Destination Port"].isin(top_ports)]

    fig = px.bar(
        filtered,
        x="Destination Port",
        y="Count",
        color="Predicted_Class",
        barmode="group",
        color_discrete_map={"BENIGN": "#38BDF8", "ATTACK": "#EF4444"},
        title="<b>Destination Port Traffic & Attack Distribution Dig</b>",
    )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#1C2541",
        plot_bgcolor="#0B132B",
        font=dict(color="#FFFFFF"),
        height=320,
        margin=dict(l=20, r=20, t=50, b=20),
        xaxis=dict(type="category"),
    )
    return fig


def create_signal_waterfall_dig(explanation_df: pd.DataFrame) -> go.Figure:
    """
    Renders an Analysis Dig Waterfall showing positive (mitigating) vs negative (escalating) signals.
    """
    df = explanation_df.copy().head(8)
    # Convert RiskScore to directional delta
    df["Delta"] = [35 if s == "Suspicious" else -20 for s in df["Status"]]

    colors = ["#EF4444" if d > 0 else "#10B981" for d in df["Delta"]]

    fig = go.Figure(
        go.Bar(
            y=df["Signal Name"],
            x=df["Delta"],
            orientation="h",
            marker=dict(color=colors),
            text=[f"+{d}% Threat" if d > 0 else f"{d}% Safe" for d in df["Delta"]],
            textposition="outside",
        )
    )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#1C2541",
        plot_bgcolor="#0B132B",
        font=dict(color="#FFFFFF"),
        title="<b>Feature Threat Attribution Dig</b> (Directional Impact on Verdict)",
        xaxis_title="Shift in Calculated Threat Probability (%)",
        yaxis_title="Inspected Attribute",
        height=340,
        margin=dict(l=20, r=60, t=50, b=20),
    )
    return fig
