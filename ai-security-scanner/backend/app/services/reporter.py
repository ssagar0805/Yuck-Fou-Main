
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from app.models.scan_response import ScanResponse, VulnerabilityFinding
from app.core.config import settings

def generate_pdf_report(scan_results: dict | ScanResponse, output_path: str) -> str:
    """
    Generates a PDF report for the scan results.
    Returns the absolute path to the generated PDF.
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=50, leftMargin=50,
        topMargin=50, bottomMargin=50
    )
    
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Title', parent=styles['Heading1'], alignment=TA_CENTER, fontSize=24, spaceAfter=20))
    styles.add(ParagraphStyle(name='Subtitle', parent=styles['Normal'], alignment=TA_CENTER, fontSize=12, spaceAfter=40))
    styles.add(ParagraphStyle(name='SectionHeader', parent=styles['Heading2'], fontSize=16, spaceBefore=20, spaceAfter=10, textColor=colors.HexColor('#131829')))
    styles.add(ParagraphStyle(name='FindingHeader', parent=styles['Heading3'], fontSize=14, spaceBefore=15, spaceAfter=5, textColor=colors.HexColor('#0056b3')))
    styles.add(ParagraphStyle(name='RiskCritical', parent=styles['Normal'], textColor=colors.red, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='RiskHigh', parent=styles['Normal'], textColor=colors.orange, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='RiskMedium', parent=styles['Normal'], textColor=colors.blue, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='RiskLow', parent=styles['Normal'], textColor=colors.green, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='CodeBlock', parent=styles['Code'], fontSize=8, backColor=colors.lightgrey, borderPadding=5, spaceAfter=10))

    story = []
    
    # Handle both ScanResponse object and dict (helper)
    if isinstance(scan_results, ScanResponse):
        # normalize to accessible object
        data = scan_results
        findings = data.findings
        # Multi-file support: if passed a single ScanResponse, treated as single file.
        # If passed a MultiFilesResponse (dict), we need to handle that. 
        # For simplicity, this reporter assumes single file report or combined report logic needs to be added.
        # Assuming single file for now based on signature.
        scan_id = data.scan_id
        risk_score = data.risk_score
        risk_level = data.risk_level
        filename = data.file_name
        timestamp = data.timestamp
        summary = getattr(data, 'summary', 'No summary provided.')
    elif isinstance(scan_results, dict) and "files" in scan_results:
        # Multi-file report
        # We'll generate a combined report.
        overall = scan_results.get("overall", {})
        scan_id = "BATCH-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        risk_score = overall.get("risk_score", 0)
        risk_level = overall.get("risk_level", "Unknown")
        filename = f"Batch Scan ({len(scan_results['files'])} files)"
        timestamp = overall.get("processed_at", datetime.now().isoformat())
        summary = f"Batch scan of {len(scan_results['files'])} files. Overall Risk: {risk_level} ({risk_score})."
        findings = [] # We will iterate files later
        
        # We need a different structure for multi-file content
        # But let's start with single file logic validation first as required by basic FR9.
        # Use simpler approach: If dict, assume it matches ScanResponse structure or MultiFilesResponse.
        
    else:
        # Fallback for strict typing or dict
        data = scan_results
        scan_id = data.get('scan_id', 'unknown')
        risk_score = data.get('risk_score', 0)
        risk_level = data.get('risk_level', 'Unknown')
        filename = data.get('file_name', 'unknown.file')
        timestamp = data.get('timestamp', datetime.now().isoformat())
        summary = data.get('summary', '')
        findings = [VulnerabilityFinding(**f) if isinstance(f, dict) else f for f in data.get('findings', [])]

    # --- 1. Title Page ---
    story.append(Paragraph(settings.APP_TITLE + " Report", styles['Title']))
    story.append(Paragraph("Confidential Security Assessment", styles['Subtitle']))
    
    # Metadata Table
    meta_data = [
        ['Scan ID:', scan_id],
        ['File Name:', filename],
        ['Date:', timestamp],
        ['Risk Score:', f"{risk_score} / 100 ({risk_level})"],
        ['Total Findings:', len(findings) if 'findings' in locals() else "See details"]
    ]
    t = Table(meta_data, colWidths=[120, 350])
    t.setStyle(TableStyle([
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,0), (0,-1), colors.whitesmoke),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 40))
    
    # --- 2. Executive Summary ---
    story.append(Paragraph("Executive Summary", styles['SectionHeader']))
    story.append(Paragraph(summary, styles['Normal']))
    story.append(Spacer(1, 10))

    # Top 3 Critical/High Issues
    story.append(Paragraph("Top Critical Risks", styles['Heading3']))
    
    all_findings_flat = []
    if isinstance(scan_results, dict) and "files" in scan_results:
        for fres in scan_results["files"]:
            fs = fres.get("findings", []) if isinstance(fres, dict) else fres.findings
            all_findings_flat.extend(fs)
    else:
        all_findings_flat = findings

    # Sort by severity (Critical=0, High=1...)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
    is_obj_chk = len(all_findings_flat) > 0 and hasattr(all_findings_flat[0], 'severity')
    sorted_all = sorted(all_findings_flat, key=lambda x: severity_order.get(x.severity if is_obj_chk else x.get('severity', 'None'), 5))
    
    top_3 = sorted_all[:3]
    if not top_3:
        story.append(Paragraph("No critical vulnerabilities found.", styles['Normal']))
    else:
        for f in top_3:
            f_obj = f if is_obj_chk else VulnerabilityFinding(**f)
            story.append(Paragraph(f"• [{f_obj.category}] {f_obj.description[:100]}...", styles['Normal']))

    story.append(Spacer(1, 20))
    
    # --- 3. Detailed Findings ---
    story.append(Paragraph("Detailed Findings", styles['SectionHeader']))
    
    if isinstance(scan_results, dict) and "files" in scan_results:
        # Multi-file loop
        for fres in scan_results["files"]:
            # fres is a ScanResponse (dict or obj)
            fname = fres.get("file_name", "Unknown") if isinstance(fres, dict) else fres.file_name
            frisk = fres.get("risk_score", 0) if isinstance(fres, dict) else fres.risk_score
            frisk_lvl = fres.get("risk_level", "Unknown") if isinstance(fres, dict) else fres.risk_level
            
            story.append(Paragraph(f"File: {fname} (Risk: {frisk_lvl})", styles['Heading3']))
            
            ffindings = fres.get("findings", []) if isinstance(fres, dict) else fres.findings
            _add_findings_to_story(ffindings, story, styles)
            story.append(Spacer(1, 20))
    else:
        # Single file
        _add_findings_to_story(findings, story, styles)

    # --- 4. Remediation Guide ---
    story.append(PageBreak())
    story.append(Paragraph("Remediation Guide", styles['SectionHeader']))
    story.append(Paragraph("Prioritized actions to secure your agent configuration:", styles['Normal']))
    story.append(Spacer(1, 10))
    
    remediations = set()
    for f in all_findings_flat:
        f_obj = f if is_obj_chk else VulnerabilityFinding(**f)
        rem = f_obj.remediation
        if rem:
            remediations.add(rem)
            
    for i, rem in enumerate(remediations, 1):
        story.append(Paragraph(f"{i}. {rem}", styles['Normal']))
        story.append(Spacer(1, 6))

    doc.build(story)
    return output_path

def _add_findings_to_story(findings, story, styles):
    if not findings:
        story.append(Paragraph("No vulnerabilities detected.", styles['Normal']))
        return

    # Sort by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
    
    # Check if finding is dict or object
    is_obj = len(findings) > 0 and hasattr(findings[0], 'severity')
    
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.severity if is_obj else x.get('severity', 'None'), 5))

    for idx, f in enumerate(sorted_findings, 1):
        f_obj = f if is_obj else VulnerabilityFinding(**f)
        
        # Color based on severity
        risk_style = styles.get(f'Risk{f_obj.severity}', styles['Normal'])
        
        header_text = f"#{idx} [{f_obj.category}] {f_obj.severity} Severity"
        story.append(Paragraph(header_text, risk_style))
        story.append(Spacer(1, 6))
        
        # Description
        story.append(Paragraph(f"<b>Description:</b> {f_obj.description}", styles['Normal']))

        # OWASP Ref
        if f_obj.owasp_reference:
             story.append(Paragraph(f"<b>OWASP Reference:</b> {f_obj.owasp_reference}", styles['Italic']))
        
        # Evidence with Line Numbers (FR7)
        if f_obj.evidence:
             story.append(Spacer(1, 4))
             evidence_lines = []
             for e in f_obj.evidence:
                 line_info = f" (Line {f_obj.line_number})" if f_obj.line_number else ""
                 evidence_lines.append(f"- {e}{line_info}")
             
             evidence_text = "<br/>".join(evidence_lines)
             t_evidence = Table([[Paragraph(f"<b>Evidence:</b><br/>{evidence_text}", styles['CodeBlock'])]], colWidths=[450])
             t_evidence.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,-1), colors.whitesmoke)]))
             story.append(t_evidence)

        # Attack Scenario
        if f_obj.attack_scenario:
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<b>Attack Scenario:</b> {f_obj.attack_scenario}", styles['Italic']))

        story.append(Spacer(1, 12))
