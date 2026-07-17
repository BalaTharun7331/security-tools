import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

os.makedirs("reports", exist_ok=True)

def generate_json(findings, target):
    filename = f"reports/xss_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump({
            "target":    target,
            "timestamp": datetime.now().isoformat(),
            "total":     len(findings),
            "findings":  findings
        }, f, indent=2)
    return filename

def generate_pdf(findings, target):
    filename = f"reports/xss_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc      = SimpleDocTemplate(filename, pagesize=letter)
    styles   = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle("title", parent=styles["Title"],
                                  textColor=colors.red, fontSize=20)
    elements.append(Paragraph("XSS Scan Report", title_style))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Target: {target}", styles["Normal"]))
    elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    elements.append(Paragraph(f"Total Vulnerabilities: {len(findings)}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    critical = len([f for f in findings if f["severity"] == "CRITICAL"])
    high     = len([f for f in findings if f["severity"] == "HIGH"])

    summary = Table([
        ["Severity", "Count"],
        ["CRITICAL",  str(critical)],
        ["HIGH",      str(high)],
        ["TOTAL",     str(len(findings))]
    ], colWidths=[200, 100])
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.darkred),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTSIZE",   (0,0), (-1,-1), 10),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,1), (-1,-1), colors.black),
        ("TEXTCOLOR",  (0,1), (-1,-1), colors.white),
    ]))
    elements.append(summary)
    elements.append(Spacer(1, 20))

    for i, f in enumerate(findings, 1):
        elements.append(Paragraph(f"Finding #{i} — {f['type']}", styles["Heading2"]))
        t = Table([
            ["Field",    "Value"],
            ["URL",      f["url"][:80]],
            ["Type",     f["type"]],
            ["Severity", f["severity"]],
            ["Payload",  f["payload"][:60]],
            ["Param",    f["param"][:40]],
            ["Method",   f["method"]],
        ], colWidths=[100, 380])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.red),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTSIZE",   (0,0), (-1,-1), 8),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
            ("BACKGROUND", (0,1), (-1,-1), colors.black),
            ("TEXTCOLOR",  (0,1), (-1,-1), colors.white),
        ]))
        elements.append(t)
        if f.get("analysis"):
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(f"AI Analysis: {f['analysis']}", styles["Normal"]))
        elements.append(Spacer(1, 16))

    doc.build(elements)
    return filename
