import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

def generate_pdf_report(scan_data: dict) -> bytes:
    """
    Builds a clean, professional PDF security assessment report from scan data.
    Uses conservative typography, clear tables, and straightforward evidence layout.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom plain, utilitarian styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#111111")
    )

    h2_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1f4e79"),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#222222")
    )

    bold_body = ParagraphStyle(
        "BoldBody",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#111111")
    )

    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#666666")
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("ThreatLens Security Intelligence Report", title_style))
    story.append(Paragraph("Automated Phishing & Malicious Website Detection", disclaimer_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc"), spaceAfter=12))

    # Basic Info Table
    target = scan_data.get("target", {})
    scoring = scan_data.get("unified_scoring", {})
    scan_ts = scan_data.get("scan_timestamp", 0)
    date_str = datetime.fromtimestamp(scan_ts).strftime("%Y-%m-%d %H:%M:%S UTC") if scan_ts else "N/A"

    info_data = [
        [Paragraph("Target URL:", bold_body), Paragraph(target.get("normalized_url", "N/A"), body_style)],
        [Paragraph("Hostname / Domain:", bold_body), Paragraph(target.get("hostname", "N/A"), body_style)],
        [Paragraph("Resolved IP(s):", bold_body), Paragraph(", ".join(target.get("resolved_ips", [])) or "Host Offline", body_style)],
        [Paragraph("Scan Timestamp:", bold_body), Paragraph(date_str, body_style)],
    ]
    info_table = Table(info_data, colWidths=[130, 400])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f9f9f8")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e5e5e0")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cccccc")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 12))

    # Unified Verdict Box
    score = scoring.get("score", 0)
    verdict = scoring.get("verdict", "UNKNOWN")
    summary = scoring.get("summary", "")

    verdict_bg = colors.HexColor("#fef2f2") if score >= 75 else (colors.HexColor("#fffbeb") if score >= 25 else colors.HexColor("#f0fdf4"))
    verdict_border = colors.HexColor("#c0392b") if score >= 75 else (colors.HexColor("#d35400") if score >= 25 else colors.HexColor("#27ae60"))

    verdict_data = [
        [
            Paragraph(f"<b>RISK SCORE: {score} / 100</b>", ParagraphStyle("Score", parent=title_style, fontSize=14, textColor=verdict_border)),
            Paragraph(f"<b>VERDICT: {verdict}</b>", ParagraphStyle("Verd", parent=title_style, fontSize=14, textColor=verdict_border))
        ],
        [
            Paragraph(summary, ParagraphStyle("Summ", parent=body_style, span=2, fontSize=9)),
            ""
        ]
    ]
    verdict_table = Table(verdict_data, colWidths=[260, 270])
    verdict_table.setStyle(TableStyle([
        ('SPAN', (0,1), (1,1)),
        ('BACKGROUND', (0,0), (-1,-1), verdict_bg),
        ('BOX', (0,0), (-1,-1), 1.5, verdict_border),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 14))

    # Evidence Breakdown Table
    story.append(Paragraph("1. Why This Verdict (Evidence Breakdown)", h2_style))
    evidence_list = scoring.get("evidence_breakdown", [])

    ev_table_data = [
        [Paragraph("Module", bold_body), Paragraph("Impact", bold_body), Paragraph("Observed Indicator", bold_body)]
    ]
    for ev in evidence_list:
        ev_table_data.append([
            Paragraph(f"<b>{ev.get('module')}</b><br/><font color='#666'>{ev.get('category')}</font>", body_style),
            Paragraph(f"<b>{ev.get('points')}</b>", bold_body),
            Paragraph(ev.get("evidence"), body_style)
        ])

    ev_table = Table(ev_table_data, colWidths=[120, 60, 350])
    ev_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#eef2f6")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 14))

    findings = scoring.get("findings", [])
    if findings:
        story.append(Paragraph("2. Atomic Findings", h2_style))
        findings_table_data = [[Paragraph("ID", bold_body), Paragraph("Severity", bold_body), Paragraph("Finding", bold_body), Paragraph("Source", bold_body)]]
        for finding in findings:
            findings_table_data.append([
                Paragraph(str(finding.get("id", "N/A")), body_style),
                Paragraph(str(finding.get("severity", "info")).upper(), body_style),
                Paragraph(str(finding.get("title") or finding.get("issue") or "No title"), body_style),
                Paragraph(str(finding.get("source", "ThreatLens")), body_style),
            ])
        findings_table = Table(findings_table_data, colWidths=[55, 75, 240, 150])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#eef2f6")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(findings_table)
        story.append(Spacer(1, 10))

    # Threat Analysis Summary
    threat = scan_data.get("threat_analysis", {})
    lookalike = threat.get("lookalike", {})
    story.append(Paragraph("2. Threat Analysis & Brand Squatting", h2_style))
    
    look_text = "No brand impersonation or typosquatting detected."
    if lookalike.get("is_lookalike"):
        look_text = f"<b>FLAGGED:</b> Impersonates <b>{lookalike.get('matched_brand')}</b> ({lookalike.get('canonical_domain')}) via {lookalike.get('technique')}."
    elif lookalike.get("is_legitimate_brand"):
        look_text = f"Verified legitimate domain belonging to <b>{lookalike.get('matched_brand')}</b>."

    ml_text = f"Random forest model probability: {threat.get('ml_probability', 0)*100:.1f}% ({threat.get('ml_engine', 'heuristics')})"
    story.append(Paragraph(f"• <b>Lookalike Analysis:</b> {look_text}", body_style))
    story.append(Paragraph(f"• <b>Machine Learning:</b> {ml_text}", body_style))
    story.append(Spacer(1, 10))

    # Web Security & Certificate Summary
    web_sec = scan_data.get("web_security", {})
    cert = scan_data.get("certificate_validation", {})
    story.append(Paragraph("3. Web Security & Certificate Health", h2_style))
    
    cert_text = "TLS handshake completed" if cert.get("has_ssl") else "No TLS / Plaintext HTTP"
    cert_text += f"; chain validation: {cert.get('chain_validation', 'Not verified')}"
    cert_text += f"; revocation: {cert.get('revocation', {}).get('status', 'Not verified')}"
    chain = cert.get("chain", [])
    if chain:
        leaf = chain[0]
        cert_text += f" (Cipher: {cert.get('cipher')}, Key: {leaf.get('key_type')} {leaf.get('key_size')}-bit, Valid to: {leaf.get('valid_to')})"

    story.append(Paragraph(f"• <b>HTTP Security Header Grade:</b> {web_sec.get('headers_grade')} ({web_sec.get('headers_score')}/100)", body_style))
    story.append(Paragraph(f"• <b>Certificate Status:</b> {cert_text}", body_style))
    story.append(Paragraph(
        "Certificate issuance and a valid chain do not establish that the website is legitimate. Revocation is reported as unverified unless checked.",
        disclaimer_style
    ))
    if cert.get("weak_key_analysis", {}).get("is_weak"):
        story.append(Paragraph(f"• <b>Weak Key Warning:</b> {', '.join(cert.get('weak_key_analysis', {}).get('reasons', []))}", body_style))

    proof = scan_data.get("on_chain_commitment")
    story.append(Paragraph("4. On-chain Proof", h2_style))
    if proof:
        proof_rows = [
            ("Network", proof.get("network")),
            ("Chain ID", proof.get("chain_id")),
            ("Contract", proof.get("contract_address")),
            ("Transaction", proof.get("tx_hash")),
            ("Block", proof.get("block_number")),
            ("Explorer", proof.get("explorer_url") or "No explorer URL configured"),
            ("Report hash", proof.get("report_hash")),
        ]
        for label, value in proof_rows:
            if value is not None:
                story.append(Paragraph(f"• <b>{label}:</b> {value}", body_style))
        story.append(Paragraph(
            "The chain attests that a hash was recorded; it does not attest to the truth of the report.",
            disclaimer_style
        ))
    else:
        story.append(Paragraph(
            "No on-chain commitment is attached to this report.",
            disclaimer_style
        ))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=8))
    story.append(Paragraph(
        "Disclaimer: ThreatLens security scan results represent algorithmic risk indicators derived from static inspection, public databases, and SSL heuristics. They do not constitute absolute legal or technical guarantees of domain legitimacy.",
        disclaimer_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
