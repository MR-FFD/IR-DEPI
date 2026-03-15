"""
PDF Report Generator for IR-DEPI
Generates professional PDF reports for phishing analysis
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import os

class PDFReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        
        # Custom styles
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#0f3460'),
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomNormal',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            fontName='Helvetica'
        ))
    
    def generate(self, result, email_path=None):
        """Generate PDF report from analysis result"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Phishing_Report_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        content = []
        
        # ===== Header =====
        content.append(Paragraph("🔐 IR-DEPI", self.styles['CustomTitle']))
        content.append(Paragraph("Enterprise Phishing Detection System", self.styles['CustomNormal']))
        content.append(Spacer(1, 0.3*inch))
        
        # ===== Verdict Section =====
        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('score', 0)
        
        # Determine color based on verdict
        if verdict == "PHISHING_DETECTED":
            verdict_color = colors.HexColor('#e74c3c')
            verdict_text = "🛑 PHISHING DETECTED"
        elif verdict == "SUSPICIOUS":
            verdict_color = colors.HexColor('#f39c12')
            verdict_text = "⚠️ SUSPICIOUS"
        else:
            verdict_color = colors.HexColor('#2ecc71')
            verdict_text = "✅ CLEAN"
        
        # Verdict Table
        verdict_data = [
            [Paragraph("Verdict", self.styles['CustomNormal']), 
             Paragraph(verdict_text, self.styles['CustomNormal'])],
            [Paragraph("Risk Score", self.styles['CustomNormal']), 
             Paragraph(f"{score}/100", self.styles['CustomNormal'])],
            [Paragraph("Analysis Date", self.styles['CustomNormal']), 
             Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.styles['CustomNormal'])]
        ]
        
        verdict_table = Table(verdict_data, colWidths=[2*inch, 3.5*inch])
        verdict_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
            ('BACKGROUND', (1, 0), (1, 0), verdict_color),
            ('TEXTCOLOR', (1, 0), (1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dddddd'))
        ]))
        
        content.append(verdict_table)
        content.append(Spacer(1, 0.3*inch))
        
        # ===== Email Metadata =====
        content.append(Paragraph("📧 Email Information", self.styles['CustomHeading']))
        
        metadata = result.get('metadata', {})
        meta_data = [
            ["Field", "Value"],
            ["Subject", metadata.get('subject', 'N/A')[:80]],
            ["From", metadata.get('from', 'N/A')],
            ["To", metadata.get('to', 'N/A')],
            ["File Path", email_path or 'N/A']
        ]
        
        meta_table = Table(meta_data, colWidths=[1.5*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dddddd')),
            ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#f5f5f5'))
        ]))
        
        content.append(meta_table)
        content.append(Spacer(1, 0.3*inch))
        
        # ===== Findings Section =====
        content.append(Paragraph("🔍 Analysis Findings", self.styles['CustomHeading']))
        
        findings = result.get('findings', [])
        
        if findings:
            findings_data = [["#", "Severity", "Category", "Description"]]
            
            for i, finding in enumerate(findings, 1):
                severity = finding.get('severity', 'INFO')
                severity_color = colors.HexColor('#e74c3c') if severity in ['CRITICAL', 'HIGH'] else \
                                colors.HexColor('#f39c12') if severity == 'MEDIUM' else \
                                colors.HexColor('#2ecc71')
                
                findings_data.append([
                    str(i),
                    Paragraph(f"<b><font color='{severity_color.hexval()}'>{severity}</font></b>", self.styles['CustomNormal']),
                    finding.get('category', 'N/A'),
                    finding.get('description', 'N/A')[:60]
                ])
            
            findings_table = Table(findings_data, colWidths=[0.5*inch, 1*inch, 1.5*inch, 2.5*inch])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dddddd')),
                ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#f9f9f9')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            
            content.append(findings_table)
        else:
            content.append(Paragraph("✅ No suspicious indicators found.", self.styles['CustomNormal']))
        
        content.append(Spacer(1, 0.3*inch))
        
        # ===== Recommendations =====
        content.append(Paragraph("💡 Recommendations", self.styles['CustomHeading']))
        
        if verdict == "PHISHING_DETECTED":
            recommendations = [
                "• Do NOT click any links in this email",
                "• Do NOT download any attachments",
                "• Report this email to your IT security team",
                "• Delete this email immediately",
                "• If you entered any credentials, change your passwords immediately"
            ]
        elif verdict == "SUSPICIOUS":
            recommendations = [
                "• Verify the sender's email address carefully",
                "• Hover over links before clicking to see actual URLs",
                "• Contact the supposed sender through official channels",
                "• When in doubt, delete the email"
            ]
        else:
            recommendations = [
                "• Continue practicing good email hygiene",
                "• Keep your security software updated",
                "• Report any suspicious emails to your IT team"
            ]
        
        for rec in recommendations:
            content.append(Paragraph(rec, self.styles['CustomNormal']))
            content.append(Spacer(1, 0.1*inch))
        
        content.append(Spacer(1, 0.3*inch))
        
        # ===== Footer =====
        content.append(Paragraph("_" * 70, self.styles['CustomNormal']))
        content.append(Paragraph(
            f"Generated by IR-DEPI v1.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['CustomNormal']
        ))
        
        # Build PDF
        doc.build(content)
        
        return filepath


# Test function
if __name__ == "__main__":
    # Test data
    test_result = {
        "verdict": "PHISHING_DETECTED",
        "score": 85,
        "metadata": {
            "subject": "URGENT: Verify Your Account",
            "from": "support@paypa1-secure.xyz",
            "to": "user@example.com"
        },
        "findings": [
            {"severity": "CRITICAL", "category": "Link", "description": "IP address in link", "evidence": "http://192.168.1.1/login"},
            {"severity": "HIGH", "category": "Sender", "description": "Free email used for brand", "evidence": "support@gmail.com"},
            {"severity": "HIGH", "category": "Content", "description": "Urgency keywords: 3", "evidence": "urgent, verify, immediately"}
        ]
    }
    
    generator = PDFReportGenerator()
    filepath = generator.generate(test_result)
    print(f"PDF Report generated: {filepath}")