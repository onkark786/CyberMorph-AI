from __future__ import annotations

import streamlit as st
from src.config import APP_SUBTITLE, APP_TITLE


def apply_custom_theme():
    """Inject premium dark cybersecurity styling across the app."""
    custom_css = """
    <style>
    :root {
        --bg: #071120;
        --bg-2: #0d1b2a;
        --panel: rgba(15, 23, 42, 0.92);
        --panel-strong: rgba(17, 24, 39, 0.96);
        --panel-soft: rgba(30, 41, 59, 0.9);
        --border: rgba(148, 163, 184, 0.18);
        --primary: #4cc9f0;
        --primary-strong: #00f2fe;
        --accent: #5eead4;
        --success: #34d399;
        --warning: #fbbf24;
        --danger: #f87171;
        --info: #60a5fa;
        --text: #e2e8f0;
        --muted: #94a3b8;
        --shadow: rgba(15, 23, 42, 0.32);
    }

    .stApp {
        background: radial-gradient(circle at top left, rgba(76, 201, 240, 0.10), transparent 28%),
                    linear-gradient(180deg, var(--bg) 0%, var(--bg-2) 100%);
        color: var(--text);
        font-family: 'Segoe UI', Inter, sans-serif;
    }

    section[data-testid="stSidebar"] {
        background: rgba(7, 17, 32, 0.96);
        border-right: 1px solid var(--border);
    }

    div[data-testid="stSidebarNav"] {
        gap: 0.4rem;
    }

    .stSidebar .stPageLink {
        border-radius: 10px;
        padding: 0.65rem 0.8rem;
        margin: 0.1rem 0;
        color: var(--text);
        border: 1px solid transparent;
    }

    .stSidebar .stPageLink:hover {
        background: rgba(76, 201, 240, 0.08);
        border-color: rgba(76, 201, 240, 0.18);
    }

    .stSidebar .stPageLink[data-selected="true"] {
        background: linear-gradient(90deg, rgba(76, 201, 240, 0.14), rgba(94, 234, 212, 0.08));
        border-color: rgba(76, 201, 240, 0.38);
        color: #ffffff;
        font-weight: 600;
    }

    div[data-testid="stMetric"] {
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.9), rgba(17, 24, 39, 0.96));
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 1rem 1.1rem;
        box-shadow: 0 10px 25px var(--shadow);
    }

    div[data-testid="stMetric"]:hover {
        border-color: rgba(76, 201, 240, 0.42);
        transform: translateY(-1px);
        transition: all 0.2s ease;
    }

    .cyber-hero {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(17, 24, 39, 0.88));
        border: 1px solid var(--border);
        border-radius: 18px;
        padding: 1.3rem 1.5rem;
        box-shadow: 0 16px 32px rgba(2, 6, 23, 0.34);
        margin-bottom: 1.2rem;
    }

    .cyber-hero-title {
        font-size: clamp(2rem, 2.6vw, 2.6rem);
        font-weight: 800;
        color: #f8fafc;
        margin: 0;
        letter-spacing: -0.04em;
    }

    .cyber-hero-subtitle {
        margin-top: 0.4rem;
        color: var(--muted);
        font-size: 0.98rem;
    }

    .cyber-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.45rem 0.8rem;
        border-radius: 999px;
        border: 1px solid var(--border);
        background: rgba(15, 23, 42, 0.8);
        color: var(--text);
        font-size: 0.78rem;
        font-weight: 600;
    }

    .pill-ready { border-color: rgba(52, 211, 153, 0.55); background: rgba(16, 185, 129, 0.12); color: #d1fae5; }
    .pill-warn { border-color: rgba(251, 191, 36, 0.55); background: rgba(251, 191, 36, 0.10); color: #fef3c7; }
    .pill-danger { border-color: rgba(248, 113, 113, 0.55); background: rgba(248, 113, 113, 0.10); color: #fee2e2; }

    .section-shell {
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 1rem 1.1rem;
        box-shadow: 0 12px 22px rgba(2, 6, 23, 0.2);
        margin-bottom: 1rem;
    }

    .section-header {
        font-size: 1.1rem;
        font-weight: 700;
        color: #f8fafc;
        margin: 0 0 0.9rem 0;
        letter-spacing: -0.02em;
    }

    .stButton > button {
        background: linear-gradient(90deg, rgba(79, 172, 254, 1), rgba(0, 242, 254, 1));
        color: #03111d !important;
        border: none;
        border-radius: 12px;
        font-weight: 700;
        padding: 0.7rem 1.1rem;
        box-shadow: 0 10px 24px rgba(79, 172, 254, 0.22);
    }

    .stButton > button:hover {
        filter: brightness(1.05);
    }

    .stDownloadButton > button {
        background: linear-gradient(90deg, rgba(13, 148, 136, 0.9), rgba(45, 212, 191, 0.9));
        color: #ecfeff !important;
    }

    div[data-testid="stDataFrame"] {
        border-radius: 12px;
        overflow: hidden;
        border: 1px solid var(--border);
    }

    hr {
        border-color: rgba(148, 163, 184, 0.22) !important;
        margin: 1.4rem 0 !important;
    }

    .cyber-alert {
        background: rgba(15, 23, 42, 0.9);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-left: 4px solid var(--primary);
        border-radius: 14px;
        padding: 0.85rem 1rem;
        color: var(--text);
    }
    </style>
    """
    st.markdown(custom_css, unsafe_allow_html=True)


def render_brand_sidebar():
    """Render a compact cybersecurity brand block in the sidebar."""
    with st.sidebar:
        st.markdown(
            f"""
            <div style="text-align: center; padding: 0.6rem 0 0.8rem 0;">
                <div style="font-size: 2.2rem; margin-bottom: 0.2rem;">🛡️</div>
                <div style="font-size: 1.2rem; font-weight: 800; color: #7dd3fc; letter-spacing: 0.04em;">{APP_TITLE}</div>
                <div style="font-size: 0.74rem; color: #94a3b8; margin-top: 0.2rem;">{APP_SUBTITLE}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.caption("SOC / AI Defense Workspace")
        st.divider()


def render_page_header(title: str, subtitle: str, icon: str = "🛡️"):
    """Render a premium hero header block for all pages."""
    st.markdown(
        f"""
        <div class="cyber-hero">
            <div style="display:flex; align-items:center; gap: 12px; flex-wrap: wrap; margin-bottom: 0.4rem;">
                <div style="font-size:1.8rem;">{icon}</div>
                <div class="cyber-hero-title">{title}</div>
            </div>
            <div class="cyber-hero-subtitle">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_status_pill(label: str, is_ready: bool, ready_text: str, not_ready_text: str) -> None:
    """Render a reusable status pill."""
    status_class = "pill-ready" if is_ready else "pill-warn"
    status_text = ready_text if is_ready else not_ready_text
    st.markdown(
        f'<div class="cyber-pill {status_class}"><span>{label}</span><span>•</span><span>{status_text}</span></div>',
        unsafe_allow_html=True,
    )
