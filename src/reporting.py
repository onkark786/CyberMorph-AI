from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Optional
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from src.config import ACADEMIC_TITLE, APP_SUBTITLE, APP_TITLE


def generate_csv_bytes(df: pd.DataFrame) -> bytes:
    """Convert a DataFrame into downloadable CSV bytes."""
    buffer = io.StringIO()
    df.to_csv(buffer, index=False)
    return buffer.getvalue().encode("utf-8")


def generate_security_pdf_report(
    overview_stats: dict[str, Any],
    phishing_meta: Optional[dict[str, Any]] = None,
    network_meta: Optional[dict[str, Any]] = None,
    recent_records: Optional[list[dict[str, Any]]] = None,
) -> bytes:
    """
    Generate an academic-grade, professional PDF security report using ReportLab.
    Returns PDF binary bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0B132B"),
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#3A506B"),
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1C2541"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#1E293B"),
    )
    meta_style = ParagraphStyle(
        "ReportMeta",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#64748B"),
    )

    elements = []

    # Title & Header
    elements.append(Paragraph(f"🛡️ {APP_TITLE} — Security Analytics Report", title_style))
    elements.append(Paragraph(APP_SUBTITLE, subtitle_style))
    elements.append(Paragraph(ACADEMIC_TITLE, meta_style))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#00F2FE"), spaceAfter=10))

    # Metadata banner
    current_time_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    meta_data = [
        [
            Paragraph(f"<b>Report Generated:</b> {current_time_utc}", meta_style),
            Paragraph("<b>Classification:</b> Defensive / Educational Audit", meta_style),
        ]
    ]
    meta_table = Table(meta_data, colWidths=[270, 260])
    elements.append(meta_table)
    elements.append(Spacer(1, 10))

    # Executive Threat Summary
    elements.append(Paragraph("1. Executive Threat Summary", section_heading))
    total_analyses = overview_stats.get("total_analyses", 0)
    total_phish = overview_stats.get("total_phishing", 0)
    malicious_phish = overview_stats.get("malicious_phishing", 0)
    net_flows = overview_stats.get("total_network_flows", 0)
    attack_flows = overview_stats.get("attack_network_flows", 0)

    summary_text = (
        f"This report consolidates threat intelligence collected by CyberMorph AI. "
        f"To date, <b>{total_analyses}</b> security evaluation sessions have been processed. "
        f"In the phishing URL classification pipeline, <b>{total_phish}</b> URLs were inspected with <b>{malicious_phish}</b> flagged as malicious. "
        f"In the network intrusion detection pipeline, <b>{net_flows}</b> flow records were analyzed, detecting <b>{attack_flows}</b> suspicious attack signatures."
    )
    elements.append(Paragraph(summary_text, body_style))
    elements.append(Spacer(1, 10))

    # Metrics Table
    elements.append(Paragraph("2. Threat KPIs & Risk Distribution", section_heading))
    kpi_data = [
        ["Security Domain", "Metric Description", "Observed Count", "Status"],
        ["Phishing Detection", "Total URLs Evaluated", str(total_phish), "Tracked"],
        ["Phishing Detection", "Confirmed Phishing Threats", str(malicious_phish), "Alert"],
        ["Phishing Detection", "Legitimate URLs Verified", str(overview_stats.get("legitimate_phishing", 0)), "Normal"],
        ["Network Intrusion", "Total Flow Records", str(net_flows), "Processed"],
        ["Network Intrusion", "Detected Attack Flows", str(attack_flows), "Alert" if attack_flows > 0 else "Clean"],
        ["High-Risk Incidents", "Severity Level: High", str(overview_stats.get("high_risk_count", 0)), "Critical"],
    ]
    t = Table(kpi_data, colWidths=[130, 190, 100, 110])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2541")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 12))

    # Model Evaluation Benchmarks
    elements.append(Paragraph("3. Machine Learning Model Benchmarks", section_heading))
    ml_data = [
        ["Model Domain", "Selected Champion", "Accuracy", "Precision", "Recall", "F1-Score"],
    ]

    if phishing_meta and "metrics" in phishing_meta:
        m = phishing_meta["metrics"]
        ml_data.append([
            "Phishing Detection",
            str(phishing_meta.get("selected_model", "Trained")),
            f"{m.get('accuracy', 0.0):.2%}",
            f"{m.get('precision', 0.0):.2%}",
            f"{m.get('recall', 0.0):.2%}",
            f"{m.get('f1_score', 0.0):.2%}",
        ])
    else:
        ml_data.append(["Phishing Detection", "Not Trained", "N/A", "N/A", "N/A", "N/A"])

    if network_meta and "metrics" in network_meta:
        m = network_meta["metrics"]
        ml_data.append([
            "Network Intrusion",
            str(network_meta.get("selected_model", "Trained")),
            f"{m.get('accuracy', 0.0):.2%}",
            f"{m.get('precision', 0.0):.2%}",
            f"{m.get('recall', 0.0):.2%}",
            f"{m.get('f1_score', 0.0):.2%}",
        ])
    else:
        ml_data.append(["Network Intrusion", "Not Trained", "N/A", "N/A", "N/A", "N/A"])

    ml_table = Table(ml_data, colWidths=[120, 130, 70, 70, 70, 70])
    ml_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B132B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("ALIGN", (2, 0), (-1, -1), "CENTER"),
    ]))
    elements.append(ml_table)
    elements.append(Spacer(1, 12))

    # Recent Activity Audit Trail
    elements.append(Paragraph("4. Recent Security Audit Log", section_heading))
    if recent_records:
        audit_data = [["ID", "Timestamp (UTC)", "Type", "Input Summary", "Prediction", "Risk"]]
        for r in recent_records[:6]:
            audit_data.append([
                str(r.get("id", "")),
                str(r.get("timestamp", ""))[:19],
                str(r.get("analysis_type", "")).capitalize(),
                str(r.get("input_summary", ""))[:32] + ("..." if len(str(r.get("input_summary", ""))) > 32 else ""),
                str(r.get("predicted_class", "")),
                str(r.get("risk_level", "")),
            ])
        audit_table = Table(audit_data, colWidths=[30, 110, 60, 190, 80, 60])
        audit_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("FONTSIZE", (0, 1), (-1, -1), 7.5),
        ]))
        elements.append(audit_table)
    else:
        elements.append(Paragraph("No audit log records currently recorded in persistent database.", meta_style))

    elements.append(Spacer(1, 14))

    # Academic Disclaimer & Limitations
    elements.append(Paragraph("5. Limitations & Academic Disclaimer", section_heading))
    disclaimer_text = (
        "<b>Notice:</b> CyberMorph AI is an academic educational framework. Predictive models are trained on historical benchmark "
        "datasets (UCI Phishing Websites and CIC-IDS2017). A classification of 'Legitimate' or 'BENIGN' does not constitute an "
        "absolute guarantee of cybersecurity safety. Live enterprise deployments require defense-in-depth, signature-based controls, "
        "and human analyst verification."
    )
    elements.append(Paragraph(disclaimer_text, meta_style))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
