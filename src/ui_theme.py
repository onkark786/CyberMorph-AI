from __future__ import annotations

from pathlib import Path
import streamlit as st
from src.config import APP_SUBTITLE, APP_TITLE, PROJECT_ROOT

ASSETS_DIR = PROJECT_ROOT / "assets"


def apply_custom_theme():
    """Inject ultra-modern high-tech SOC cybersecurity CSS styles into Streamlit."""
    custom_css = """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

    /* Global Typography and App Surface */
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    .stApp {
        background-color: #080D1A;
        background-image: 
            radial-gradient(at 0% 0%, rgba(0, 242, 254, 0.07) 0px, transparent 50%),
            radial-gradient(at 100% 100%, rgba(67, 100, 247, 0.08) 0px, transparent 50%),
            linear-gradient(rgba(8, 13, 26, 0.95), rgba(8, 13, 26, 0.95));
        color: #F8FAFC;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #050811 0%, #0B1124 100%) !important;
        border-right: 1px solid rgba(0, 242, 254, 0.15);
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.4);
    }

    /* Metric Cards - Glassmorphism & Neon Edge */
    div[data-testid="stMetric"] {
        background: rgba(18, 26, 49, 0.75) !important;
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(58, 80, 107, 0.5) !important;
        border-radius: 12px !important;
        padding: 16px 20px !important;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3) !important;
        transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
    }

    div[data-testid="stMetric"]:hover {
        transform: translateY(-2px);
        border-color: #00F2FE !important;
        box-shadow: 0 10px 28px rgba(0, 242, 254, 0.15) !important;
    }

    div[data-testid="stMetric"] label {
        color: #94A3B8 !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #FFFFFF !important;
        font-weight: 800 !important;
        font-size: 1.8rem !important;
    }

    /* Primary Futuristic Action Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #0052D4 0%, #4364F7 50%, #00F2FE 100%) !important;
        color: #FFFFFF !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
        font-size: 0.95rem !important;
        padding: 10px 22px !important;
        box-shadow: 0 4px 18px rgba(0, 82, 212, 0.4) !important;
        letter-spacing: 0.3px;
        transition: all 0.2s ease !important;
    }

    .stButton > button:hover {
        transform: translateY(-1px) scale(1.01) !important;
        box-shadow: 0 6px 24px rgba(0, 242, 254, 0.5) !important;
    }

    /* Analysis Dig Callout Cards */
    .dig-card {
        background: rgba(22, 33, 62, 0.65);
        border: 1px solid rgba(0, 242, 254, 0.25);
        border-left: 5px solid #00F2FE;
        border-radius: 10px;
        padding: 16px 20px;
        margin: 14px 0;
        box-shadow: 0 4px 16px rgba(0,0,0,0.25);
    }

    .dig-title {
        font-size: 1rem;
        font-weight: 700;
        color: #00F2FE;
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 6px;
    }

    .dig-body {
        font-size: 0.88rem;
        color: #CBD5E1;
        line-height: 1.5;
    }

    /* Risk Badges */
    .cyber-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }

    .badge-high {
        background: rgba(239, 68, 68, 0.18);
        color: #EF4444;
        border: 1px solid #EF4444;
        box-shadow: 0 0 10px rgba(239, 68, 68, 0.2);
    }

    .badge-medium {
        background: rgba(245, 158, 11, 0.18);
        color: #F59E0B;
        border: 1px solid #F59E0B;
        box-shadow: 0 0 10px rgba(245, 158, 11, 0.2);
    }

    .badge-low {
        background: rgba(16, 185, 129, 0.18);
        color: #10B981;
        border: 1px solid #10B981;
        box-shadow: 0 0 10px rgba(16, 185, 129, 0.2);
    }

    /* Tabs Styling */
    div[data-baseweb="tab-list"] {
        background-color: #0F172A;
        border-radius: 10px;
        padding: 4px;
        border: 1px solid #1E293B;
    }

    div[data-baseweb="tab"] {
        border-radius: 8px;
        font-weight: 600;
        color: #94A3B8;
        padding: 8px 16px;
    }

    div[data-baseweb="tab"][aria-selected="true"] {
        background: linear-gradient(135deg, #1E293B 0%, #2A3B5C 100%) !important;
        color: #00F2FE !important;
        border: 1px solid rgba(0, 242, 254, 0.3) !important;
    }

    /* Clean Code and Json */
    div[data-testid="stJson"], pre {
        background-color: #0B1120 !important;
        border: 1px solid #1E293B !important;
        border-radius: 8px !important;
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Image rounding */
    div[data-testid="stImage"] img {
        border-radius: 12px;
        border: 1px solid rgba(58, 80, 107, 0.5);
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
    }
    </style>
    """
    st.markdown(custom_css, unsafe_allow_html=True)


def render_brand_sidebar():
    """Render consistent branding and live system telemetry in the sidebar."""
    with st.sidebar:
        st.markdown(
            f"""
            <div style="text-align: center; padding: 14px 0 16px 0;">
                <div style="font-size: 2.8rem; filter: drop-shadow(0 0 12px #00F2FE);">🛡️</div>
                <div style="font-size: 1.4rem; font-weight: 800; background: linear-gradient(90deg, #00F2FE, #4FACFE); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: 0.5px;">
                    {APP_TITLE}
                </div>
                <div style="font-size: 0.76rem; color: #94A3B8; margin-top: 2px;">
                    {APP_SUBTITLE}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            """
            <div style="background: rgba(18, 26, 49, 0.6); border: 1px solid #2A3B5C; border-radius: 8px; padding: 10px 14px; margin-bottom: 12px;">
                <div style="font-size: 0.72rem; color: #64748B; text-transform: uppercase; font-weight: 700;">Engine Status</div>
                <div style="font-size: 0.85rem; color: #10B981; font-weight: 600; margin-top: 2px;">● ALL SYSTEMS ONLINE</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.divider()

        st.caption("🔒 Architecture: **Explainable Cyber AI**")
        st.caption("⚡ Model Engine: **Scikit-Learn Pipelines**")
        st.caption("💾 Persistent Store: **SQLite3 Storage**")
        st.caption("📑 Generator: **ReportLab PDF Engine**")
        st.divider()


def render_page_header(title: str, subtitle: str, icon: str = "🛡️"):
    """Standardized glowing header block."""
    st.markdown(
        f"""
        <div style="margin-bottom: 24px; padding-bottom: 12px; border-bottom: 1px solid rgba(58, 80, 107, 0.4);">
            <h1 style="display: flex; align-items: center; gap: 12px; margin: 0; color: #FFFFFF; font-size: 2.1rem; font-weight: 800;">
                <span style="filter: drop-shadow(0 0 8px #00F2FE);">{icon}</span> {title}
            </h1>
            <p style="color: #94A3B8; font-size: 1.02rem; margin-top: 8px; line-height: 1.4;">
                {subtitle}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_analysis_dig_box(title: str, explanation: str, takeaways: list[str]):
    """Renders a styled analysis dig card with key visual insights for beginners."""
    takeaways_html = "".join([f"<li style='margin-bottom: 4px;'>{t}</li>" for t in takeaways])
    st.markdown(
        f"""
        <div class="dig-card">
            <div class="dig-title">🔍 {title}</div>
            <div class="dig-body">
                <p style="margin-bottom: 8px;">{explanation}</p>
                <ul style="margin: 0; padding-left: 20px; color: #E2E8F0; font-size: 0.85rem;">
                    {takeaways_html}
                </ul>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
