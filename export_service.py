"""
Aegis Export Service
====================
Provides a unified export dispatcher for scan assessments in multiple formats:
  - PDF: Formatted executive & technical assessment report with visual risk badges,
         Aegis branding, findings table with auto-wrapping, deterministic remediation,
         and cached AI insights.
  - CSV: Structured tabular export with formula injection escaping.
  - JSON: Standardized JSON payload with schema_version 1.0.
  - TXT: Plain-text legacy format for backward compatibility.
"""

import csv
import io
import json
import logging
import os
from flask import Response, jsonify

from database import (
    get_ai_analysis,
    get_command_executions_for_scan,
    get_scan_details,
)
from risk_analyzer import calculate_security_score
from scanner import SCAN_PROFILES
from service_fingerprints import get_service_fingerprint

logger = logging.getLogger(__name__)

# CSV Formula Injection prefix trigger characters
CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value):
    """
    Sanitize CSV field to prevent CSV Formula Injection.
    If the cell content starts with dangerous formula trigger characters
    (=, +, -, @, \\t, \\r), prefix it with a single quote (').
    """
    if value is None:
        return ""
    str_val = str(value)
    if str_val.startswith(CSV_INJECTION_PREFIXES):
        return f"'{str_val}"
    return str_val


def get_scan_export_context(scan_id):
    """
    Retrieves full scan metadata, port findings with deterministic remediation,
    and any cached AI analysis.
    """
    scan = get_scan_details(scan_id)
    if not scan:
        return None

    profile_id = scan.get("profile_id", "quick")
    profile_info = SCAN_PROFILES.get(profile_id, SCAN_PROFILES.get("quick", {
        "name": "Standard Profile",
        "flags": "-F"
    }))

    ai_data = get_ai_analysis(scan_id)
    cmd_execs = get_command_executions_for_scan(scan_id)

    return {
        "scan": scan,
        "profile_id": profile_id,
        "profile_name": profile_info.get("name", "Quick Scan"),
        "nmap_flags": profile_info.get("flags", "-F"),
        "ai_data": ai_data,
        "command_executions": cmd_execs or []
    }


# ============================================================================
# TXT Export
# ============================================================================
def generate_txt_export(ctx):
    """Generate plain-text report matching original Aegis format with Security Score."""
    scan = ctx["scan"]
    scan_id = scan["id"]
    score_info = scan.get("security_score") or calculate_security_score(scan.get("ports", []))
    score_str = (
        f"{score_info['score']}/100 ({score_info['label']})"
        if score_info.get("available") and score_info.get("score") is not None
        else "UNAVAILABLE"
    )

    lines = [
        "AEGIS PORT SCANNER REPORT",
        "=" * 26,
        f"Scan ID: {scan_id}",
        f"Target: {scan['target']}",
        f"Timestamp: {scan['scan_time']}",
        f"Overall risk: {scan['overall_risk']}",
        f"Security score: {score_str}",
        f"Scan profile: {ctx['profile_name']}",
        f"Nmap flags: {ctx['nmap_flags']}",
        f"Open ports: {scan['open_port_count']}",
        "",
        "SECURITY SCORE BREAKDOWN",
        "-" * 26,
        f"Score: {score_str}",
        f"Base score: {score_info.get('base_score', 100)} points",
        f"Total deduction: -{score_info.get('total_deduction', 0)} points",
    ]
    for d in score_info.get("deductions", []):
        lines.append(f"  - Port {d['port']}/{d['protocol']} ({d['service']}): -{d['points_deducted']} pts ({d['risk']}) - {d['reason']}")
    if not score_info.get("deductions"):
        lines.append("  No exposure risk deductions applied (0 open ports).")
    lines.extend([
        "",
        f"Disclaimer: {score_info.get('disclaimer', '')}",
        "",
        "FINDINGS",
        "-" * 26,
    ])
    for finding in scan.get("ports", []):
        fp = finding.get("fingerprint", {}) or {}
        cat_str = f" [{fp.get('category', 'Unclassified')}]" if fp.get("category") else ""
        lines.extend([
            f"Port: {finding['port']}/{finding.get('protocol', 'tcp')} ({finding.get('state', 'open')})",
            f"Service: {finding.get('service', 'unknown')}{cat_str}",
            f"Risk: {finding.get('risk', 'LOW')}",
            f"Reason: {finding.get('reason', '')}",
            "",
        ])
    if not scan.get("ports"):
        lines.append("No open TCP ports were recorded.")

    ai_data = ctx.get("ai_data")
    if ai_data and "analysis" in ai_data:
        analysis = ai_data["analysis"]
        lines.extend([
            "",
            "AI SECURITY ASSESSMENT",
            "-" * 26,
            f"Model: {ai_data.get('model', 'Aegis AI Analyst')}",
            f"Assessment Date: {ai_data.get('created_at', '')}",
            "",
            "Summary:",
            analysis.get("summary", ""),
            "",
            "Priority Recommendations:",
        ])
        for rec in analysis.get("recommendations", []):
            lines.append(f"  {rec}")
        lines.extend([
            "",
            "Beginner Explanation:",
            analysis.get("beginner_explanation", ""),
        ])

    cmd_execs = ctx.get("command_executions", [])
    if cmd_execs:
        lines.extend([
            "",
            "ADDITIONAL COPILOT DIAGNOSTIC AUDITS & WEB OBSERVATIONS",
            "-" * 55,
        ])
        for ex in cmd_execs:
            lines.extend([
                f"Execution #{ex['id']} — Tool: {ex.get('tool', 'nmap')} | Operation: {ex.get('operation_id', 'custom')}",
                f"Command: {ex.get('command_str')}",
                f"Timestamp: {ex.get('start_time', ex.get('created_at', ''))} | Status: {ex.get('status', 'completed')}",
            ])
            p_findings = ex.get("parsed_findings") or {}
            f_list = p_findings.get("findings", [])
            if f_list:
                lines.append(f"Discovered Ports ({len(f_list)}):")
                for f in f_list:
                    lines.append(f"  - Port {f['port']}/{f.get('protocol', 'tcp')}: {f.get('service', 'unknown')} (Risk: {f.get('risk', 'LOW')}) - {f.get('reason', '')}")
            w_obs = p_findings.get("web_observations", [])
            if w_obs:
                if isinstance(w_obs, dict):
                    w_obs = [w_obs]
                lines.append(f"Web Service Observations ({len(w_obs)}):")
                for w in w_obs:
                    if not isinstance(w, dict):
                        continue
                    port_label = f"Port {w.get('port')}" if w.get('port') else "Endpoint"
                    lines.append(f"  - {w.get('scheme', 'http').upper()} {port_label}: Status {w.get('status_code', 'N/A')} · Server: {w.get('server_header', 'Undisclosed')} · Title: {w.get('html_title', 'None')}")
            ai_exp = ex.get("ai_analysis") or {}
            if ai_exp.get("summary"):
                lines.append(f"Analyst Summary: {ai_exp['summary']}")
            lines.append("")

    return Response(
        "\n".join(lines),
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=aegis-scan-{scan_id}.txt"},
    )


# ============================================================================
# CSV Export
# ============================================================================
def generate_csv_export(ctx):
    """Generate structured CSV export with formula injection sanitization and Security Score."""
    scan = ctx["scan"]
    scan_id = scan["id"]
    score_info = scan.get("security_score") or calculate_security_score(scan.get("ports", []))
    score_val = (
        str(score_info.get("score"))
        if score_info.get("available") and score_info.get("score") is not None
        else "UNAVAILABLE"
    )
    score_label = score_info.get("label", "UNAVAILABLE")

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    headers = [
        "Scan_ID",
        "Target",
        "Scan_Time",
        "Overall_Risk",
        "Security_Score",
        "Security_Score_Label",
        "Scan_Profile",
        "Nmap_Flags",
        "Port",
        "Protocol",
        "State",
        "Service",
        "Service_Category",
        "Port_Risk",
        "Risk_Reason",
        "Remediation_Summary",
        "Verification_Command"
    ]
    writer.writerow(headers)

    ports = scan.get("ports", [])
    if not ports:
        # Zero open ports row
        writer.writerow([
            sanitize_csv_cell(scan_id),
            sanitize_csv_cell(scan["target"]),
            sanitize_csv_cell(scan["scan_time"]),
            sanitize_csv_cell(scan["overall_risk"]),
            sanitize_csv_cell(score_val),
            sanitize_csv_cell(score_label),
            sanitize_csv_cell(ctx["profile_name"]),
            sanitize_csv_cell(ctx["nmap_flags"]),
            "None",
            "None",
            "closed/filtered",
            "None",
            "None",
            "LOW",
            "No open TCP ports detected.",
            "Maintain current host firewall posture.",
            f"nmap -F {scan['target']}"
        ])
    else:
        for p in ports:
            rem = p.get("remediation", {}) or {}
            fp = p.get("fingerprint", {}) or {}
            category = fp.get("category", "Unclassified")
            writer.writerow([
                sanitize_csv_cell(scan_id),
                sanitize_csv_cell(scan["target"]),
                sanitize_csv_cell(scan["scan_time"]),
                sanitize_csv_cell(scan["overall_risk"]),
                sanitize_csv_cell(score_val),
                sanitize_csv_cell(score_label),
                sanitize_csv_cell(ctx["profile_name"]),
                sanitize_csv_cell(ctx["nmap_flags"]),
                sanitize_csv_cell(p.get("port")),
                sanitize_csv_cell(p.get("protocol", "tcp")),
                sanitize_csv_cell(p.get("state", "open")),
                sanitize_csv_cell(p.get("service", "unknown")),
                sanitize_csv_cell(category),
                sanitize_csv_cell(p.get("risk", "LOW")),
                sanitize_csv_cell(p.get("reason", "")),
                sanitize_csv_cell(rem.get("summary", "")),
                sanitize_csv_cell(rem.get("verification", ""))
            ])

    # Append any findings from additional approved Copilot command executions
    seen_ports = {f"{p.get('protocol', 'tcp')}:{p.get('port')}" for p in ports}
    for ex in ctx.get("command_executions", []):
        p_findings = ex.get("parsed_findings") or {}
        for f in p_findings.get("findings", []):
            pkey = f"{f.get('protocol', 'tcp')}:{f.get('port')}"
            if pkey not in seen_ports:
                seen_ports.add(pkey)
                rem = f.get("remediation", {}) or {}
                fp = f.get("fingerprint", {}) or {}
                writer.writerow([
                    sanitize_csv_cell(scan_id),
                    sanitize_csv_cell(scan["target"]),
                    sanitize_csv_cell(ex.get("start_time", scan["scan_time"])),
                    sanitize_csv_cell(f.get("risk", "LOW")),
                    sanitize_csv_cell(score_val),
                    sanitize_csv_cell(score_label),
                    sanitize_csv_cell(f"Copilot ({ex.get('operation_id')})"),
                    sanitize_csv_cell(ex.get("command_str")),
                    sanitize_csv_cell(f.get("port")),
                    sanitize_csv_cell(f.get("protocol", "tcp")),
                    sanitize_csv_cell(f.get("state", "open")),
                    sanitize_csv_cell(f.get("service", "unknown")),
                    sanitize_csv_cell(fp.get("category", "Unclassified")),
                    sanitize_csv_cell(f.get("risk", "LOW")),
                    sanitize_csv_cell(f.get("reason", "")),
                    sanitize_csv_cell(rem.get("summary", "")),
                    sanitize_csv_cell(rem.get("verification", ""))
                ])

    csv_data = output.getvalue()
    return Response(
        csv_data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=aegis-scan-{scan_id}.csv"},
    )


# ============================================================================
# JSON Export
# ============================================================================
def generate_json_export(ctx):
    """Generate standardized JSON export adhering to schema version 1.0."""
    scan = ctx["scan"]
    scan_id = scan["id"]
    ai_data = ctx.get("ai_data")
    score_info = scan.get("security_score") or calculate_security_score(scan.get("ports", []))

    ai_export = None
    if ai_data and "analysis" in ai_data:
        ai_export = {
            "model": ai_data.get("model", "Aegis AI Analyst"),
            "created_at": ai_data.get("created_at", ""),
            "analysis": ai_data["analysis"]
        }

    payload = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "target": scan["target"],
        "scan_time": scan["scan_time"],
        "overall_risk": scan["overall_risk"],
        "security_score": score_info,
        "open_port_count": scan["open_port_count"],
        "profile": {
            "id": ctx["profile_id"],
            "name": ctx["profile_name"],
            "nmap_flags": ctx["nmap_flags"]
        },
        "ports": scan.get("ports", []),
        "ai_analysis": ai_export,
        "additional_command_executions": ctx.get("command_executions", []),
        "copilot_command_executions": ctx.get("command_executions", [])
    }

    json_str = json.dumps(payload, indent=2, ensure_ascii=False)
    return Response(
        json_str,
        mimetype="application/json; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=aegis-scan-{scan_id}.json"},
    )


# ============================================================================
# PDF Export (ReportLab)
# ============================================================================
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    Image,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render total page count
    alongside confidentiality notice and running footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_footer(num_pages)
            super().showPage()
        super().save()

    def draw_footer(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(HexColor("#64748B"))  # Slate 500

        # Separator line
        self.setStrokeColor(HexColor("#E2E8F0"))  # Slate 200
        self.setLineWidth(0.75)
        self.line(36, 42, 612 - 36, 42)

        # Footer text
        disclaimer = "CONFIDENTIAL • Aegis Security Platform • For Authorized Security Assessment Only"
        self.drawString(36, 30, disclaimer)
        self.drawRightString(612 - 36, 30, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def get_risk_colors(risk):
    """Returns primary and background HexColor pair for risk ratings."""
    risk_upper = str(risk).upper()
    if risk_upper == "HIGH":
        return HexColor("#DC2626"), HexColor("#FEE2E2")
    elif risk_upper == "MEDIUM":
        return HexColor("#D97706"), HexColor("#FEF3C7")
    return HexColor("#059669"), HexColor("#D1FAE5")


def get_score_colors(label):
    """Returns primary and background HexColor pair for security score band labels."""
    lbl = str(label).upper().strip()
    if lbl == "GOOD":
        return HexColor("#059669"), HexColor("#D1FAE5")
    elif lbl == "FAIR":
        return HexColor("#0D9488"), HexColor("#CCFBF1")
    elif lbl == "NEEDS IMPROVEMENT":
        return HexColor("#D97706"), HexColor("#FEF3C7")
    elif lbl == "POOR":
        return HexColor("#EA580C"), HexColor("#FFEDD5")
    elif lbl == "CRITICAL":
        return HexColor("#DC2626"), HexColor("#FEE2E2")
    return HexColor("#64748B"), HexColor("#F1F5F9")


def generate_pdf_export(ctx):
    """
    Generate professional executive PDF report with ReportLab.
    Includes branding, scan metadata, colored risk summary, repeating table
    headers, deterministic remediation playbook, and cached AI assessment.
    """
    scan = ctx["scan"]
    scan_id = scan["id"]
    ai_data = ctx.get("ai_data")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=40,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=HexColor("#0F172A"),
        spaceAfter=2,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=13,
        textColor=HexColor("#64748B"),
        spaceAfter=12,
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=HexColor("#1E293B"),
        spaceBefore=14,
        spaceAfter=6,
    )
    sub_heading = ParagraphStyle(
        "SubHeading",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=HexColor("#334155"),
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=HexColor("#334155"),
    )
    body_bold = ParagraphStyle(
        "BodyDarkBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )
    table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=HexColor("#1E293B"),
    )
    table_header_cell = ParagraphStyle(
        "TableHeaderCell",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=11,
        textColor=HexColor("#FFFFFF"),
    )
    code_cell = ParagraphStyle(
        "CodeCell",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=HexColor("#0F172A"),
    )
    callout_text = ParagraphStyle(
        "CalloutText",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=11,
        textColor=HexColor("#475569"),
    )

    story = []

    # 1. Header with Aegis Logo & Title
    base_dir = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(base_dir, "static", "logo.png")

    header_cells = []
    if os.path.exists(logo_path):
        logo_img = Image(logo_path, width=125, height=30)
        logo_img.hAlign = "LEFT"
        header_cells.append(logo_img)
    else:
        header_cells.append(Paragraph("<b>AEGIS</b>", title_style))

    title_block = [
        Paragraph("AEGIS SECURITY ASSESSMENT REPORT", title_style),
        Paragraph("Deterministic Port Exposure, Risk Evaluation & Remediation Playbook", subtitle_style),
    ]

    header_table = Table(
        [[header_cells[0], title_block]],
        colWidths=[135, 405]
    )
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#E2E8F0"), spaceAfter=12))

    # 2. Scan Metadata Grid & Overall Risk Badge & Security Score Badge
    overall_risk = str(scan.get("overall_risk", "LOW")).upper()
    risk_color, risk_bg = get_risk_colors(overall_risk)

    badge_cell = [
        Paragraph("<b>OVERALL RISK</b>", ParagraphStyle(
            "BadgeLabel", fontName="Helvetica-Bold", fontSize=7.5, leading=9, textColor=risk_color, alignment=1
        )),
        Paragraph(f"<b>{overall_risk}</b>", ParagraphStyle(
            "BadgeVal", fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=risk_color, alignment=1
        ))
    ]

    score_info = scan.get("security_score") or calculate_security_score(scan.get("ports", []))
    score_val = (
        f"{score_info['score']}/100"
        if score_info.get("available") and score_info.get("score") is not None
        else "N/A"
    )
    score_label = score_info.get("label", "UNAVAILABLE")
    score_col, score_bg = get_score_colors(score_label)

    score_badge_cell = [
        Paragraph("<b>SECURITY SCORE</b>", ParagraphStyle(
            "ScoreBadgeLabel", fontName="Helvetica-Bold", fontSize=7.5, leading=9, textColor=score_col, alignment=1
        )),
        Paragraph(f"<b>{score_val}</b>", ParagraphStyle(
            "ScoreBadgeVal", fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=score_col, alignment=1
        )),
        Paragraph(f"<b>{score_label}</b>", ParagraphStyle(
            "ScoreBadgeSub", fontName="Helvetica-Bold", fontSize=7, leading=8, textColor=score_col, alignment=1
        ))
    ]

    meta_table_data = [
        [
            Paragraph("<b>Target Host:</b>", body_style),
            Paragraph(f"<code>{scan['target']}</code>", body_style),
            Paragraph("<b>Scan ID:</b>", body_style),
            Paragraph(str(scan_id), body_style),
            badge_cell,
            score_badge_cell
        ],
        [
            Paragraph("<b>Timestamp:</b>", body_style),
            Paragraph(scan.get("scan_time", "N/A"), body_style),
            Paragraph("<b>Open Ports:</b>", body_style),
            Paragraph(str(scan.get("open_port_count", 0)), body_style),
            "",
            ""
        ],
        [
            Paragraph("<b>Scan Profile:</b>", body_style),
            Paragraph(ctx["profile_name"], body_style),
            Paragraph("<b>Nmap Flags:</b>", body_style),
            Paragraph(f"<code>{ctx['nmap_flags']}</code>", body_style),
            "",
            ""
        ]
    ]

    meta_table = Table(
        meta_table_data,
        colWidths=[65, 120, 65, 80, 105, 105]
    )
    meta_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("SPAN", (4, 0), (4, 2)),  # Span risk badge cell across 3 rows
        ("BACKGROUND", (4, 0), (4, 2), risk_bg),
        ("BOX", (4, 0), (4, 2), 1.5, risk_color),
        ("SPAN", (5, 0), (5, 2)),  # Span score badge cell across 3 rows
        ("BACKGROUND", (5, 0), (5, 2), score_bg),
        ("BOX", (5, 0), (5, 2), 1.5, score_col),
        ("BACKGROUND", (0, 0), (3, 2), HexColor("#F8FAFC")),
        ("BOX", (0, 0), (3, 2), 1, HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (3, 2), 0.5, HexColor("#EDF2F7")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # 3. Security Score Breakdown Section
    story.append(Paragraph("DETERMINISTIC SECURITY SCORE BREAKDOWN", section_heading))
    score_summary_str = (
        f"<b>Base Score:</b> {score_info.get('base_score', 100)} points &nbsp;|&nbsp; "
        f"<b>Configured Weights:</b> HIGH (-25), MEDIUM (-10), LOW (-3) &nbsp;|&nbsp; "
        f"<b>Total Deductions:</b> -{score_info.get('total_deduction', 0)} points &nbsp;|&nbsp; "
        f"<b>Final Score:</b> <b>{score_val} ({score_label})</b>"
    )
    story.append(Paragraph(score_summary_str, body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(score_info.get("disclaimer", ""), callout_text))
    story.append(Spacer(1, 6))

    deductions = score_info.get("deductions", [])
    if deductions:
        deduct_data = [
            [
                Paragraph("Port / Proto", table_header_cell),
                Paragraph("Service", table_header_cell),
                Paragraph("Risk", table_header_cell),
                Paragraph("Penalty", table_header_cell),
                Paragraph("Exposure Reason", table_header_cell)
            ]
        ]
        for d in deductions:
            d_risk = str(d.get("risk", "LOW")).upper()
            d_col, _ = get_risk_colors(d_risk)
            deduct_data.append([
                Paragraph(f"<b>{d.get('port')}/{d.get('protocol', 'tcp')}</b>", table_cell),
                Paragraph(str(d.get("service", "unknown")), table_cell),
                Paragraph(f"<b><font color='{d_col.hexval()}'>{d_risk}</font></b>", table_cell),
                Paragraph(f"<b>-{d.get('points_deducted')} pts</b>", table_cell),
                Paragraph(d.get("reason", ""), table_cell)
            ])
        deduct_table = Table(deduct_data, colWidths=[65, 75, 60, 55, 285])
        deduct_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1E293B")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 1, HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(deduct_table)
    else:
        empty_deduct = Table(
            [[Paragraph("<b>No risk penalties were deducted.</b> Zero open TCP listening ports were detected under the scan profile.", callout_text)]],
            colWidths=[540]
        )
        empty_deduct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 0.75, HexColor("#CBD5E1")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(empty_deduct)

    story.append(Spacer(1, 10))

    # 3. Discovered Port Findings Table
    story.append(Paragraph("DISCOVERED PORT FINDINGS", section_heading))

    ports = scan.get("ports", [])
    if not ports:
        empty_box = Table(
            [[Paragraph("<b>No open TCP ports detected.</b> All scanned ports were reported closed or filtered.", callout_text)]],
            colWidths=[540]
        )
        empty_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 1, HexColor("#CBD5E1")),
            ("PADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(empty_box)
        story.append(Spacer(1, 14))
    else:
        findings_data = [
            [
                Paragraph("Port / Proto", table_header_cell),
                Paragraph("State", table_header_cell),
                Paragraph("Service", table_header_cell),
                Paragraph("Risk", table_header_cell),
                Paragraph("Technical Exposure Details", table_header_cell)
            ]
        ]

        table_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1E293B")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 1, HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]

        for idx, p in enumerate(ports, start=1):
            p_risk = str(p.get("risk", "LOW")).upper()
            p_col, p_bg = get_risk_colors(p_risk)
            row_bg = HexColor("#FFFFFF") if idx % 2 != 0 else HexColor("#F8FAFC")
            table_styles.append(("BACKGROUND", (0, idx), (-1, idx), row_bg))

            risk_cell = Paragraph(f"<b><font color='{p_col.hexval()}'>{p_risk}</font></b>", table_cell)

            findings_data.append([
                Paragraph(f"<b>{p.get('port')}/{p.get('protocol', 'tcp')}</b>", table_cell),
                Paragraph(str(p.get("state", "open")), table_cell),
                Paragraph(str(p.get("service", "unknown")), table_cell),
                risk_cell,
                Paragraph(p.get("reason", "N/A"), table_cell)
            ])

        findings_table = Table(
            findings_data,
            colWidths=[65, 45, 75, 55, 300],
            repeatRows=1  # Repeat header row on split pages
        )
        findings_table.setStyle(TableStyle(table_styles))
        story.append(findings_table)
        story.append(Spacer(1, 14))

    # 4. Deterministic Remediation & Service Fingerprint Playbook Section
    if ports:
        story.append(Paragraph("DETERMINISTIC REMEDIATION & SERVICE INTELLIGENCE PLAYBOOK", section_heading))
        story.append(Paragraph(
            "The following hardened mitigation playbooks and service fingerprint profiles provide educational context, "
            "protocol knowledge, and actionable commands for authorized administrators. Commands are illustrative templates "
            "and are never executed directly by Aegis.",
            callout_text
        ))
        story.append(Spacer(1, 8))

        for p in ports:
            rem = p.get("remediation", {}) or {}
            port_num = p.get("port")
            service_name = str(p.get("service", "unknown")).upper()
            p_risk = str(p.get("risk", "LOW")).upper()
            p_col, _ = get_risk_colors(p_risk)

            fp = p.get("fingerprint") or get_service_fingerprint(
                port_num,
                p.get("service"),
                profile_id=ctx.get("profile_id", "quick"),
                deterministic_risk=p_risk
            )
            cat_name = fp.get("category", "General Network Service")
            display_title = fp.get("display_name", f"Port {port_num} ({service_name})")

            port_story = []
            port_story.append(Paragraph(
                f"<b>Port {port_num} — {display_title} &nbsp;|&nbsp; Category: {cat_name} — <font color='{p_col.hexval()}'>{p_risk} RISK</font></b>",
                sub_heading
            ))

            if fp.get("description"):
                port_story.append(Paragraph(f"<b>Protocol Description:</b> {fp['description']}", body_style))
                port_story.append(Spacer(1, 3))
            if fp.get("common_security_concerns"):
                port_story.append(Paragraph(f"<b>Security Concerns:</b> {fp['common_security_concerns']}", body_style))
                port_story.append(Spacer(1, 3))
            if fp.get("public_exposure_guidance"):
                port_story.append(Paragraph(f"<b>Exposure Guidance:</b> {fp['public_exposure_guidance']}", body_style))
                port_story.append(Spacer(1, 3))
            if fp.get("associated_attacks"):
                port_story.append(Paragraph(f"<b>Threat Context:</b> {fp['associated_attacks']}", callout_text))
                port_story.append(Spacer(1, 4))

            if rem.get("summary"):
                port_story.append(Paragraph(f"<b>Hardening Summary:</b> {rem['summary']}", body_style))
                port_story.append(Spacer(1, 4))

            # Action steps
            steps = rem.get("steps", [])
            if steps:
                port_story.append(Paragraph("<b>Recommended Hardening Steps:</b>", body_bold))
                for step in steps:
                    port_story.append(Paragraph(f"• {step}", body_style))
                port_story.append(Spacer(1, 4))

            # Platform commands table
            platform = rem.get("platform", {})
            cmd_rows = []
            if platform.get("linux"):
                cmd_str = "<br/>".join([f"$ {cmd}" for cmd in platform["linux"]])
                cmd_rows.append([Paragraph("<b>Linux</b>", body_style), Paragraph(cmd_str, code_cell)])
            if platform.get("windows"):
                cmd_str = "<br/>".join([f"PS> {cmd}" for cmd in platform["windows"]])
                cmd_rows.append([Paragraph("<b>Windows</b>", body_style), Paragraph(cmd_str, code_cell)])
            if platform.get("firewall"):
                cmd_str = "<br/>".join([f"# {cmd}" for cmd in platform["firewall"]])
                cmd_rows.append([Paragraph("<b>Firewall</b>", body_style), Paragraph(cmd_str, code_cell)])

            if cmd_rows:
                cmd_table = Table(cmd_rows, colWidths=[65, 475])
                cmd_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 0.75, HexColor("#CBD5E1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#E2E8F0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]))
                port_story.append(cmd_table)
                port_story.append(Spacer(1, 4))

            # Verification command & Warnings
            if rem.get("verification"):
                port_story.append(Paragraph(f"<b>Verification:</b> <code>{rem['verification']}</code>", body_style))
            if rem.get("warnings"):
                port_story.append(Paragraph(f"<b>Operational Warning:</b> {rem['warnings']}", callout_text))

            refs = fp.get("references", [])
            if refs:
                ref_titles = "; ".join([f"{r.get('title', '')} ({r.get('url', '')})" for r in refs])
                port_story.append(Paragraph(f"<b>Documentation:</b> {ref_titles}", callout_text))

            port_story.append(Spacer(1, 10))
            story.extend(port_story)

    # 5. Cached AI Security Assessment Section (if available)
    if ai_data and "analysis" in ai_data:
        ai_analysis = ai_data["analysis"]
        story.append(Spacer(1, 10))
        story.append(Paragraph("POST-SCAN AI SECURITY ASSESSMENT", section_heading))

        meta_info = (
            f"<b>Model:</b> {ai_data.get('model', 'Aegis AI Analyst')} &nbsp;|&nbsp; "
            f"<b>Assessment Date:</b> {ai_data.get('created_at', 'N/A')}"
        )
        story.append(Paragraph(meta_info, callout_text))
        story.append(Spacer(1, 6))

        if ai_analysis.get("summary"):
            story.append(Paragraph("<b>Executive Summary:</b>", body_bold))
            story.append(Paragraph(ai_analysis["summary"], body_style))
            story.append(Spacer(1, 6))

        recs = ai_analysis.get("recommendations", [])
        if recs:
            story.append(Paragraph("<b>Priority Recommendations:</b>", body_bold))
            for r in recs:
                story.append(Paragraph(f"• {r}", body_style))
            story.append(Spacer(1, 6))

        if ai_analysis.get("beginner_explanation"):
            story.append(Paragraph("<b>Beginner Explanation:</b>", body_bold))
            story.append(Paragraph(ai_analysis["beginner_explanation"], body_style))
            story.append(Spacer(1, 6))

        story.append(Paragraph(
            "<i>Note: AI analysis is generated from cached scan assessments. Deterministic findings remain the authoritative source of truth.</i>",
            callout_text
        ))

    # 6. Additional Copilot Diagnostic Command Audits & Web Observations
    cmd_execs = ctx.get("command_executions", [])
    if cmd_execs:
        story.append(Spacer(1, 10))
        story.append(Paragraph("AI COPILOT COMMAND AUDITS & EXTENDED FINDINGS", section_heading))
        for ex in cmd_execs:
            story.append(Paragraph(
                f"<b>Command:</b> <code>{ex.get('command_str')}</code> &nbsp;|&nbsp; "
                f"<b>Tool:</b> {ex.get('tool', 'nmap')} &nbsp;|&nbsp; "
                f"<b>Status:</b> {ex.get('status', 'completed')} &nbsp;|&nbsp; "
                f"<b>Timestamp:</b> {ex.get('start_time', ex.get('created_at', ''))}",
                callout_text
            ))
            story.append(Spacer(1, 4))
            p_findings = ex.get("parsed_findings") or {}
            f_list = p_findings.get("findings", [])
            if f_list:
                for f in f_list:
                    f_risk = str(f.get("risk", "LOW")).upper()
                    f_col, _ = get_risk_colors(f_risk)
                    story.append(Paragraph(
                        f"• <b>Port {f['port']}/{f.get('protocol', 'tcp')}</b> — "
                        f"<b><font color='{f_col.hexval()}'>{f_risk}</font></b>: "
                        f"{f.get('service', 'unknown')} - {f.get('reason', '')}",
                        body_style
                    ))
            w_obs = p_findings.get("web_observations", [])
            if w_obs:
                if isinstance(w_obs, dict):
                    w_obs = [w_obs]
                for w in w_obs:
                    if not isinstance(w, dict):
                        continue
                    port_info = f"{w.get('scheme', 'http').upper()}:{w.get('port', '')}" if w.get('port') else "HTTP/S"
                    story.append(Paragraph(
                        f"• <b>Web Endpoint ({port_info}):</b> "
                        f"HTTP {w.get('status_code', 'N/A')} · Server: <i>{w.get('server_header', 'Undisclosed')}</i> · Title: {w.get('html_title', 'None')}",
                        body_style
                    ))
            ai_exp = ex.get("ai_analysis") or {}
            if ai_exp.get("summary"):
                story.append(Paragraph(f"<b>Analyst Insight:</b> {ai_exp['summary']}", body_style))
            story.append(Spacer(1, 6))

    doc.build(story, canvasmaker=NumberedCanvas)
    pdf_bytes = buffer.getvalue()

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=aegis-scan-{scan_id}.pdf"},
    )


# ============================================================================
# Unified Export Dispatcher
# ============================================================================
SUPPORTED_FORMATS = ("txt", "pdf", "csv", "json")


def dispatch_export(scan_id, format_type="txt"):
    """
    Unified entry point for scan report exports.
    Dispatches to format-specific generator or returns HTTP 400 / 404 / 500.
    """
    clean_format = str(format_type).lower().strip() if format_type else "txt"

    if clean_format not in SUPPORTED_FORMATS:
        return jsonify({
            "status": "error",
            "message": f"Unsupported export format '{format_type}'. Supported formats are: {', '.join(SUPPORTED_FORMATS)}."
        }), 400

    try:
        ctx = get_scan_export_context(scan_id)
        if not ctx:
            return jsonify({
                "status": "error",
                "message": "Scan not found."
            }), 404

        if clean_format == "txt":
            return generate_txt_export(ctx)
        elif clean_format == "csv":
            return generate_csv_export(ctx)
        elif clean_format == "json":
            return generate_json_export(ctx)
        elif clean_format == "pdf":
            return generate_pdf_export(ctx)

    except Exception:
        logger.exception("Error exporting scan %s in format %s", scan_id, format_type)
        return jsonify({
            "status": "error",
            "message": "Failed to export scan report."
        }), 500
