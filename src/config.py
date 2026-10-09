from __future__ import annotations

import os
from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"
PHISHING_DATA_DIR = DATA_DIR / "phishing"
NETWORK_DATA_DIR = DATA_DIR / "network"

MODELS_DIR = PROJECT_ROOT / "models"
PHISHING_MODEL_DIR = MODELS_DIR / "phishing"
NETWORK_MODEL_DIR = MODELS_DIR / "network"

REPORTS_DIR = PROJECT_ROOT / "reports"
DOCS_DIR = PROJECT_ROOT / "docs"

# Database
DB_PATH = DATA_DIR / "cybermorph.db"

# Ensure runtime directories exist
for folder in [
    DATA_DIR,
    PHISHING_DATA_DIR,
    NETWORK_DATA_DIR,
    MODELS_DIR,
    PHISHING_MODEL_DIR,
    NETWORK_MODEL_DIR,
    REPORTS_DIR,
    DOCS_DIR,
]:
    folder.mkdir(parents=True, exist_ok=True)

# Application Identity & UI Constants
APP_TITLE = "CyberMorph AI"
APP_SUBTITLE = "Intelligent Cyber Threat Detection & Analytics"
ACADEMIC_TITLE = (
    "CyberMorph AI: An Explainable Machine Learning-Based Framework for "
    "Phishing Detection, Network Intrusion Detection and Cyber Threat Analytics"
)

# Color Scheme Constants (Dark Navy & Modern Security Palette)
THEME_COLORS = {
    "bg_dark": "#0B132B",
    "card_dark": "#1C2541",
    "card_border": "#3A506B",
    "accent_cyan": "#00F2FE",
    "accent_blue": "#4FACFE",
    "text_primary": "#FFFFFF",
    "text_secondary": "#94A3B8",
    "risk_high": "#EF4444",
    "risk_medium": "#F59E0B",
    "risk_low": "#10B981",
    "risk_neutral": "#64748B",
}
