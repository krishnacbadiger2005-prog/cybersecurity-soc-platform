"""
Security Lab Telemetry Reporting Module
Generates CSV and PDF security monitoring reports for authentication events and security alerts.
"""
import csv
import io
from datetime import datetime

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        KeepTogether,
        HRFlowable
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


def _safe_get(item, key, default=""):
    """Safely get a key from dict, sqlite3.Row, or tuple object."""
    if item is None:
        return default
    if isinstance(item, dict):
        return item.get(key, default)
    if hasattr(item, "__getitem__"):
        try:
            return item[key]
        except (KeyError, IndexError, TypeError):
            pass
        if hasattr(item, "_dict"):
            return item._dict.get(key, default)
    return getattr(item, key, default)


def generate_security_report(events, alerts, start_date=None, end_date=None):
    """
    Generate in-memory CSV report containing:
      1. Report summary & metrics (Total Attempts, Successful, Failed, Suspicious IPs, Alerts)
      2. Detailed Authentication Events
      3. Detailed Security Alerts
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Calculate summary metrics
    total_attempts = len(events)
    successful = sum(1 for event in events if _safe_get(event, "status") == "SUCCESS")
    failed = sum(1 for event in events if _safe_get(event, "status") == "FAILED")

    suspicious_ips = set()
    for alert in alerts:
        ip = _safe_get(alert, "ip_address")
        if ip:
            suspicious_ips.add(ip)

    # Step 6: Period row
    period_str = f"{start_date} to {end_date}" if (start_date and end_date) else "All Time"

    # Write Summary section
    writer.writerow(["Security Monitoring Report"])
    writer.writerow(["Period", period_str])
    writer.writerow(["Total Attempts", total_attempts])
    writer.writerow(["Successful", successful])
    writer.writerow(["Failed", failed])
    writer.writerow(["Suspicious IPs", len(suspicious_ips)])
    writer.writerow(["Alerts Generated", len(alerts)])

    # Step 12: Blank line + Authentication Events section
    writer.writerow([])
    writer.writerow(["Authentication Events"])
    writer.writerow([
        "ID",
        "Username",
        "IP Address",
        "Status",
        "Timestamp"
    ])

    for event in events:
        event_id = _safe_get(event, "id", "")
        username = _safe_get(event, "username", "")
        ip_address = _safe_get(event, "ip_address", "")
        status = _safe_get(event, "status", "")
        timestamp = _safe_get(event, "timestamp", "")
        writer.writerow([
            event_id,
            username,
            ip_address,
            status,
            timestamp
        ])

    # Step 15: Security Alerts section
    writer.writerow([])
    writer.writerow(["Security Alerts"])
    writer.writerow([
        "ID",
        "IP Address",
        "Attempts",
        "Severity",
        "Description",
        "Timestamp"
    ])

    for alert in alerts:
        alert_id = _safe_get(alert, "id", "")
        ip_address = _safe_get(alert, "ip_address", "")
        attempts = _safe_get(alert, "attempt_count", _safe_get(alert, "attempts", ""))
        severity = _safe_get(alert, "severity", "HIGH")
        desc = _safe_get(alert, "description", f"Repeated failed logins ({attempts} attempts)")
        timestamp = _safe_get(alert, "timestamp", "")
        writer.writerow([
            alert_id,
            ip_address,
            attempts,
            severity,
            desc,
            timestamp
        ])

    return output.getvalue()


def _init_reportlab():
    global HAS_REPORTLAB, SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable, getSampleStyleSheet, ParagraphStyle, letter, colors
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            KeepTogether,
            HRFlowable
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        HAS_REPORTLAB = True
    except Exception:
        HAS_REPORTLAB = False
    return HAS_REPORTLAB


def _generate_fallback_pdf(events, alerts, start_date=None, end_date=None):
    """
    Pure Python standard PDF 1.4 generator fallback.
    Ensures PDF export succeeds even if ReportLab binary dependencies fail.
    """
    period_str = f"{start_date} to {end_date}" if (start_date and end_date) else "All Recorded Activity"
    total_attempts = len(events)
    successful = sum(1 for e in events if _safe_get(e, "status") == "SUCCESS")
    failed = sum(1 for e in events if _safe_get(e, "status") == "FAILED")
    suspicious_ips = set(_safe_get(a, "ip_address") for a in alerts if _safe_get(a, "ip_address"))

    lines = [
        "SECURITY MONITORING REPORT",
        f"Reporting Period: {period_str}",
        "-" * 55,
        "EXECUTIVE SUMMARY",
        f"  Total Authentication Attempts: {total_attempts}",
        f"  Successful Logins:             {successful}",
        f"  Failed Logins:                 {failed}",
        f"  Suspicious IP Addresses:       {len(suspicious_ips)}",
        f"  Security Alerts Generated:     {len(alerts)}",
        "-" * 55,
        "AUTHENTICATION ACTIVITY",
        f"{'ID':<6} {'Username':<14} {'IP Address':<16} {'Status':<10} {'Timestamp'}"
    ]

    for event in events[:35]:
        eid = str(_safe_get(event, "id", ""))
        user = str(_safe_get(event, "username", ""))[:13]
        ip = str(_safe_get(event, "ip_address", ""))[:15]
        st = str(_safe_get(event, "status", ""))[:9]
        ts = str(_safe_get(event, "timestamp", ""))
        lines.append(f"{eid:<6} {user:<14} {ip:<16} {st:<10} {ts}")

    if not events:
        lines.append("  (No authentication events recorded in this period)")

    lines.append("-" * 55)
    lines.append("SECURITY ALERTS")
    lines.append(f"{'IP Address':<16} {'Attempts':<10} {'Severity':<10} {'Timestamp'}")

    for alert in alerts[:15]:
        ip = str(_safe_get(alert, "ip_address", ""))[:15]
        att = str(_safe_get(alert, "attempt_count", _safe_get(alert, "attempts", "")))[:9]
        sev = str(_safe_get(alert, "severity", "HIGH"))[:9]
        ts = str(_safe_get(alert, "timestamp", ""))
        lines.append(f"{ip:<16} {att:<10} {sev:<10} {ts}")

    if not alerts:
        lines.append("  (No security alerts generated during this period)")

    lines.append("-" * 55)
    lines.append("DETECTION RULE SPECIFICATION")
    lines.append("  Rule: Repeated failed authentication attempts")
    lines.append("  Threshold: 5 failures within 10 minutes")

    stream_content = "BT\n/F1 14 Tf\n50 750 Td\n(SECURITY MONITORING REPORT) Tj\nET\n"
    y = 730
    for line in lines[1:]:
        escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        font_size = 8 if ("-" in line or "  " in line) else 9
        stream_content += f"BT\n/F1 {font_size} Tf\n50 {y} Td\n({escaped}) Tj\nET\n"
        y -= 13
        if y < 40:
            break

    stream_bytes = stream_content.encode("latin1", errors="replace")
    stream_len = len(stream_bytes)

    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
        f"4 0 obj\n<< /Length {stream_len} >>\nstream\n".encode("latin1") + stream_bytes + b"\nendstream\nendobj\n",
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n"
    ]

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for obj in objects:
        offsets.append(out.tell())
        out.write(obj)

    xref_pos = out.tell()
    out.write(b"xref\n0 6\n0000000000 65535 f \n")
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode("latin1"))

    out.write(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("latin1"))
    return out.getvalue()


def _build_reportlab_pdf(events, alerts, start_date=None, end_date=None):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#475569'),
        spaceAfter=14
    )

    section_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=12,
        spaceAfter=6
    )

    cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#1e293b')
    )

    cell_bold_style = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#1e293b')
    )

    cell_header_style = ParagraphStyle(
        'CellHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.white
    )

    story = []

    # Title & Header
    story.append(Paragraph("SECURITY MONITORING REPORT", title_style))
    period_str = f"{start_date} → {end_date}" if (start_date and end_date) else "All Recorded Activity"
    story.append(Paragraph(f"<b>Reporting Period:</b> {period_str}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#6366f1'), spaceAfter=14))

    # Calculate metrics
    total_attempts = len(events)
    successful = sum(1 for e in events if _safe_get(e, "status") == "SUCCESS")
    failed = sum(1 for e in events if _safe_get(e, "status") == "FAILED")
    suspicious_ips = set(_safe_get(a, "ip_address") for a in alerts if _safe_get(a, "ip_address"))

    # Executive Summary Section
    story.append(Paragraph("SUMMARY", section_style))
    summary_data = [
        [Paragraph("Metric", cell_header_style), Paragraph("Value", cell_header_style)],
        [Paragraph("Total Authentication Attempts", cell_style), Paragraph(str(total_attempts), cell_bold_style)],
        [Paragraph("Successful Logins", cell_style), Paragraph(str(successful), cell_bold_style)],
        [Paragraph("Failed Logins", cell_style), Paragraph(str(failed), cell_bold_style)],
        [Paragraph("Suspicious IP Addresses", cell_style), Paragraph(str(len(suspicious_ips)), cell_bold_style)],
        [Paragraph("Security Alerts", cell_style), Paragraph(str(len(alerts)), cell_bold_style)],
    ]
    summary_table = Table(summary_data, colWidths=[350, 190])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # Authentication Activity Table
    story.append(Paragraph("AUTHENTICATION ACTIVITY", section_style))
    auth_headers = ["ID", "Username", "IP Address", "Status", "Timestamp"]
    auth_data = [[Paragraph(h, cell_header_style) for h in auth_headers]]

    if events:
        for event in events[:100]:
            st = str(_safe_get(event, "status", ""))
            status_color = "#10b981" if st == "SUCCESS" else "#f43f5e"
            status_p = Paragraph(f"<font color='{status_color}'><b>{st}</b></font>", cell_style)

            auth_data.append([
                Paragraph(str(_safe_get(event, "id", "")), cell_style),
                Paragraph(str(_safe_get(event, "username", "")), cell_bold_style),
                Paragraph(str(_safe_get(event, "ip_address", "")), cell_style),
                status_p,
                Paragraph(str(_safe_get(event, "timestamp", "")), cell_style)
            ])
    else:
        auth_data.append([Paragraph("No authentication events recorded for this period.", cell_style), "", "", "", ""])

    auth_table = Table(auth_data, colWidths=[40, 130, 120, 80, 170])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    if not events:
        auth_table.setStyle(TableStyle([('SPAN', (0, 1), (-1, 1))]))
    story.append(auth_table)
    story.append(Spacer(1, 14))

    # Security Alerts Table
    story.append(Paragraph("SECURITY ALERTS", section_style))
    alert_headers = ["IP Address", "Attempts", "Severity", "Description", "Timestamp"]
    alert_data = [[Paragraph(h, cell_header_style) for h in alert_headers]]

    if alerts:
        for alert in alerts[:50]:
            attempts = str(_safe_get(alert, "attempt_count", _safe_get(alert, "attempts", "")))
            sev = str(_safe_get(alert, "severity", "HIGH"))
            sev_color = "#dc2626" if sev == "CRITICAL" else ("#ea580c" if sev == "HIGH" else "#d97706")
            sev_p = Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", cell_style)
            desc = str(_safe_get(alert, "description", f"Repeated failed logins ({attempts} attempts)"))

            alert_data.append([
                Paragraph(str(_safe_get(alert, "ip_address", "")), cell_bold_style),
                Paragraph(attempts, cell_style),
                sev_p,
                Paragraph(desc, cell_style),
                Paragraph(str(_safe_get(alert, "timestamp", "")), cell_style)
            ])
    else:
        alert_data.append([Paragraph("No security alerts generated during this period.", cell_style), "", "", "", ""])

    alert_table = Table(alert_data, colWidths=[120, 60, 70, 150, 140])
    alert_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#475569')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    if not alerts:
        alert_table.setStyle(TableStyle([('SPAN', (0, 1), (-1, 1))]))
    story.append(alert_table)
    story.append(Spacer(1, 14))

    # Detection Rule Specification (Step 28)
    rule_content = [
        Paragraph("<b>DETECTION RULE SPECIFICATION</b>", ParagraphStyle('RuleHead', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#0f172a'))),
        Spacer(1, 4),
        Paragraph("<b>Condition:</b> Repeated failed authentication attempts", cell_style),
        Paragraph("<b>Threshold:</b> 5 failures", cell_style),
        Paragraph("<b>Window:</b> 10 minutes", cell_style),
        Paragraph("<b>Action:</b> IP address automatically flagged as SUSPICIOUS and Security Alert generated.", cell_style),
    ]
    rule_table = Table([[rule_content]], colWidths=[540])
    rule_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#e0e7ff')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#6366f1')),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(KeepTogether(rule_table))

    doc.build(story)
    return buffer.getvalue()


def generate_security_pdf(events, alerts, start_date=None, end_date=None):
    """
    Generate professional PDF report using ReportLab with:
      - Title & Period Banner
      - Executive Summary Metrics Table
      - Authentication Activity Table
      - Security Alerts Table
      - SOC Detection Rule Specification Box
    Falls back gracefully to pure-Python PDF if ReportLab is unavailable.
    """
    if not HAS_REPORTLAB:
        _init_reportlab()

    if HAS_REPORTLAB:
        try:
            return _build_reportlab_pdf(events, alerts, start_date, end_date)
        except Exception:
            pass

    return _generate_fallback_pdf(events, alerts, start_date, end_date)

