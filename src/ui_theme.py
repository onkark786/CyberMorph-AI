from __future__ import annotations

import streamlit as st
from src.config import APP_SUBTITLE, APP_TITLE


def apply_custom_theme():
    """Apply shared refinements to the configured Streamlit theme."""
    custom_css = """
    <style>
    :root {
        --bg: #071120;
        --bg-2: #0d1b2a;
        --panel: rgba(15, 23, 42, 0.82);
        --panel-strong: rgba(17, 24, 39, 0.94);
        --panel-soft: rgba(30, 41, 59, 0.72);
        --border: rgba(148, 163, 184, 0.2);
        --primary: #38bdf8;
        --accent: #67e8f9;
        --success: #34d399;
        --warning: #fbbf24;
        --danger: #f87171;
        --info: #60a5fa;
        --text: #e2e8f0;
        --muted: #94a3b8;
        --shadow: rgba(15, 23, 42, 0.32);
    }

    .stApp {
        background:
            radial-gradient(ellipse at 12% 0%, rgba(56, 189, 248, 0.08), transparent 34%),
            linear-gradient(180deg, var(--bg) 0%, var(--bg-2) 100%);
        color: var(--text);
    }

    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 2.5rem;
        max-width: 1560px;
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
        background: rgba(56, 189, 248, 0.08);
        border-color: rgba(56, 189, 248, 0.2);
    }

    .stSidebar .stPageLink[data-selected="true"] {
        background: linear-gradient(90deg, rgba(56, 189, 248, 0.14), rgba(103, 232, 249, 0.07));
        border-color: rgba(56, 189, 248, 0.38);
        color: #ffffff;
        font-weight: 600;
    }

    div[data-testid="stMetric"] {
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.88), rgba(17, 24, 39, 0.94));
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 0.85rem 1rem;
        box-shadow: 0 8px 20px var(--shadow);
    }

    div[data-testid="stMetricLabel"] {
        color: #b6c5d6;
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
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 1rem 1.1rem;
        box-shadow: 0 8px 20px rgba(2, 6, 23, 0.18);
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
        background: linear-gradient(100deg, #38bdf8, #67e8f9);
        color: #03111d !important;
        border: none;
        border-radius: 9px;
        font-weight: 700;
        padding: 0.62rem 1rem;
        box-shadow: 0 6px 16px rgba(56, 189, 248, 0.16);
    }

    .stButton > button:hover {
        filter: brightness(1.05);
    }

    .stButton > button:focus-visible,
    .stDownloadButton > button:focus-visible,
    a:focus-visible {
        outline: 3px solid #a5f3fc;
        outline-offset: 2px;
    }

    .stDownloadButton > button {
        border-color: rgba(103, 232, 249, 0.45);
    }

    div[data-testid="stDataFrame"] {
        border-radius: 10px;
        overflow: hidden;
        border: 1px solid var(--border);
    }

    div[data-testid="stFileUploader"],
    div[data-testid="stTextInput"] input,
    div[data-testid="stTextArea"] textarea,
    div[data-testid="stSelectbox"] > div > div,
    div[data-testid="stMultiSelect"] > div > div {
        border-color: var(--border);
    }

    div[data-testid="stTabs"] button[role="tab"] {
        font-weight: 600;
    }

    hr {
        border-color: rgba(148, 163, 184, 0.22) !important;
        margin: 1.1rem 0 !important;
    }

    .cyber-alert {
        background: rgba(15, 23, 42, 0.9);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-left: 3px solid var(--primary);
        border-radius: 10px;
        padding: 0.85rem 1rem;
        color: var(--text);
    }

    @media (max-width: 768px) {
        .block-container {
            padding-top: 1rem;
            padding-left: 1rem;
            padding-right: 1rem;
        }

        .cyber-hero {
            padding: 1rem;
        }

        .cyber-hero-title {
            font-size: 1.65rem;
        }
    }

    @media (prefers-reduced-motion: reduce) {
        *,
        *::before,
        *::after {
            scroll-behavior: auto !important;
            transition-duration: 0.01ms !important;
        }
    }
    </style>
    """
    st.markdown(custom_css, unsafe_allow_html=True)


def render_brand_sidebar():
    """Render a compact cybersecurity brand block in the sidebar."""
    with st.sidebar:
        st.markdown(f"### :material/security: {APP_TITLE}")
        st.caption(APP_SUBTITLE)
        st.caption("SOC / AI defense workspace")
        st.divider()


def render_page_header(title: str, subtitle: str, icon: str = "🛡️"):
    """Render a premium hero header block for all pages."""
    with st.container(border=True):
        st.title(title, icon=icon)
        st.caption(subtitle)


def render_status_pill(label: str, is_ready: bool, ready_text: str, not_ready_text: str) -> None:
    """Render a reusable status pill."""
    status_class = "pill-ready" if is_ready else "pill-warn"
    status_text = ready_text if is_ready else not_ready_text
    st.markdown(
        f'<div class="cyber-pill {status_class}"><span>{label}</span><span>•</span><span>{status_text}</span></div>',
        unsafe_allow_html=True,
    )
