#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║              🛡️  N A T I V E           ║
║           Phishing Email Detection System                    ║
║              Version 1.0.0 | © 2026                          ║
╚═══════════════════════════════════════════════════════════════╝
Developer: M. Refat
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import email, re, os, sys
from datetime import datetime

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    PDF_OK = True
except: PDF_OK = False

# ==================== Enterprise Configuration ====================
APP, VER = "NATIVE", "1.0.0"
LOG_FILE, REPORTS = "native.log", "reports"
os.makedirs(REPORTS, exist_ok=True)

def log(msg):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
    except: pass

# ==================== ENTERPRISE PHISHING DATABASE ====================
class PhishingDatabase:
    """Comprehensive enterprise-level phishing signature database"""
    
    # High-Risk TLDs (Categorized by risk level)
    TLD_CRITICAL = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.loan', '.vip']  # 35 points
    TLD_HIGH = ['.top', '.work', '.click', '.link', '.info', '.biz']  # 25 points
    TLD_MEDIUM = ['.space', '.site', '.website', '.store', '.tech', '.online', '.live', '.rent']  # 15 points
    
    # Urgency Keywords (Categorized by severity)
    URGENCY_CRITICAL = ['urgent', 'immediately', 'suspended', 'terminated', 'account locked', 'legal action']
    URGENCY_HIGH = ['verify now', 'action required', 'confirm now', 'expire', 'limited time', 'last chance', 'act now']
    URGENCY_MEDIUM = ['click here', 'update now', 'respond immediately', 'don\'t miss', 'expires in']
    
    # Phishing Brands (Commonly impersonated)
    PHISHING_BRANDS = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix',
                       'dhl', 'fedex', 'ups', 'usps', 'bank of america', 'wells fargo', 'chase',
                       'citibank', 'irs', 'social security', 'linkedin', 'dropbox', 'adobe']
    
    # Sensitive Data Request Patterns (Context-aware - REDUCED FALSE POSITIVES)
    SENSITIVE_CRITICAL = [
        'send your password', 'confirm your password', 'verify your password',
        'enter your password', 'provide your password', 'update your password',
        'credit card number', 'credit card details', 'cvv code', 'card security code',
        'bank account verification', 'routing number', 'account verification',
        'social security number', 'ssn verification', 'national id',
        'enter your credentials', 'provide your login', 'verify your credentials',
        'pin number', 'security code', 'authentication code', 'otp code'
    ]
    
    # Legitimate Business Contexts (EXCLUSIONS - Prevents False Positives)
    LEGITIMATE_CONTEXTS = [
        'salary transfer', 'payroll', 'direct deposit', 'employee benefits',
        'tax purposes', 'hr department', 'human resources', 'onboarding',
        'new employee', 'welcome to the team', 'first day', 'bank account details for salary',
        'account information for payroll', 'direct deposit information'
    ]
    
    # Suspicious URL Patterns
    URL_PATTERNS = [
        r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP-based URLs
        r'bit\.ly/', r'tinyurl\.com/', r'goo\.gl/', r'ow\.ly/',  # URL shorteners
    ]
    
    # Generic Greetings (Impersonal)
    GENERIC_GREETINGS = [
        'dear customer', 'dear user', 'dear member', 'dear sir', 'dear madam',
        'valued customer', 'dear account holder', 'dear client', 'dear subscriber',
        'greetings user', 'hello customer', 'dear email owner'
    ]


# ==================== Detection Engine ====================
def analyze(path):
    """Enterprise-grade email analysis with comprehensive detection"""
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_string(f.read())
    except Exception as e: return {'error': str(e)}
    
    subject = msg.get('Subject', 'No Subject')[:60]
    sender = msg.get('From', 'Unknown')[:50]
    date = msg.get('Date', 'Unknown')[:30]
    
    # Extract body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try: body = part.get_payload(decode=True).decode('utf-8', errors='ignore'); break
                except: pass
    else:
        try: body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        except: body = str(msg.get_payload())
    
    body_lower = body.lower()
    subject_lower = subject.lower()
    sender_lower = sender.lower()
    
    findings, score, checks = [], 0, []
    
    # ========== CHECK 1: IP-Based URLs (CRITICAL - 40 points) ==========
    ip_urls = re.findall(r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', body)
    if ip_urls:
        findings.append({'severity': 'CRITICAL', 'category': 'Link Analysis', 
                        'description': f'IP-based URL detected ({len(ip_urls)} found)', 
                        'details': 'Legitimate services rarely use IP addresses in links'})
        score += 40
    checks.append("IP Link Analysis")
    
    # ========== CHECK 2: Urgency Language (HIGH - 25 points) ==========
    urgency_found = []
    for word in PhishingDatabase.URGENCY_CRITICAL + PhishingDatabase.URGENCY_HIGH:
        if word in body_lower or word in subject_lower:
            urgency_found.append(word)
    
    if urgency_found:
        findings.append({'severity': 'HIGH', 'category': 'Language Analysis',
                        'description': f'Urgency/pressure language detected ({len(urgency_found)} keywords)', 
                        'details': f'Keywords: {", ".join(urgency_found[:5])}'})
        score += 25
    checks.append("Language Pattern Analysis")
    
    # ========== CHECK 3: Suspicious Domains (CRITICAL/HIGH - 25-35 points) ==========
    domain_score = 0
    detected_tld = None
    tld_category = ""
    
    for tld in PhishingDatabase.TLD_CRITICAL:
        if tld in sender_lower:
            detected_tld = tld
            domain_score = 35
            tld_category = "CRITICAL"
            break
    
    if domain_score == 0:
        for tld in PhishingDatabase.TLD_HIGH:
            if tld in sender_lower:
                detected_tld = tld
                domain_score = 25
                tld_category = "HIGH"
                break
    
    if domain_score == 0:
        for tld in PhishingDatabase.TLD_MEDIUM:
            if tld in sender_lower:
                detected_tld = tld
                domain_score = 15
                tld_category = "MEDIUM"
                break
    
    if detected_tld:
        findings.append({'severity': 'HIGH' if domain_score >= 25 else 'MEDIUM', 
                        'category': 'Sender Analysis',
                        'description': f'Suspicious domain extension detected', 
                        'details': f'Domain uses {tld_category}-risk TLD: {detected_tld}'})
        score += domain_score
    checks.append("Domain Reputation Check")
    
    # ========== CHECK 4: Generic Greeting (MEDIUM - 15 points) ==========
    for greeting in PhishingDatabase.GENERIC_GREETINGS:
        if greeting in body_lower:
            findings.append({'severity': 'MEDIUM', 'category': 'Greeting Analysis',
                            'description': 'Generic impersonal greeting detected', 
                            'details': 'Legitimate organizations typically use personalized greetings'})
            score += 15
            break
    checks.append("Greeting Pattern Analysis")
    
    # ========== CHECK 5: Sensitive Data Request (CRITICAL - 30 points) ==========
    # CONTEXT-AWARE: Check for legitimate business contexts FIRST
    is_legitimate = False
    for context in PhishingDatabase.LEGITIMATE_CONTEXTS:
        if context in body_lower:
            is_legitimate = True
            break
    
    # Only flag if NOT in legitimate context
    if not is_legitimate:
        for pattern in PhishingDatabase.SENSITIVE_CRITICAL:
            if pattern in body_lower:
                findings.append({'severity': 'CRITICAL', 'category': 'Data Request',
                                'description': 'Request for sensitive information detected', 
                                'details': 'Legitimate organizations never request sensitive data via email'})
                score += 30
                break
    checks.append("Data Request Analysis")
    
    # ========== CHECK 6: Brand Impersonation (MEDIUM - 20 points) ==========
    for brand in PhishingDatabase.PHISHING_BRANDS:
        if brand in sender_lower and brand not in body_lower:
            findings.append({'severity': 'MEDIUM', 'category': 'Brand Analysis',
                            'description': f'Potential brand impersonation: {brand.title()}', 
                            'details': 'Sender domain doesn\'t match claimed brand'})
            score += 20
            break
    checks.append("Brand Verification")
    
    # ========== CHECK 7: URL Shorteners (MEDIUM - 15 points) ==========
    for pattern in PhishingDatabase.URL_PATTERNS[1:]:  # Skip IP patterns (already checked)
        if re.search(pattern, body, re.IGNORECASE):
            findings.append({'severity': 'MEDIUM', 'category': 'Link Analysis',
                            'description': 'URL shortener detected', 
                            'details': 'Shortened URLs can hide malicious destinations'})
            score += 15
            break
    checks.append("URL Pattern Analysis")
    
    # ========== Determine Verdict (LOWERED THRESHOLDS) ==========
    if score >= 50: verdict, verdict_text, risk, color = "PHISHING", "🔴 Phishing Detected", "CRITICAL", "#c0392b"
    elif score >= 15: verdict, verdict_text, risk, color = "SUSPICIOUS", "🟡 Suspicious", "MODERATE", "#f39c12"  # Lowered from 20 to 15
    else: verdict, verdict_text, risk, color = "CLEAN", "🟢 Clean", "LOW", "#27ae60"
    
    return {
        'file': os.path.basename(path), 'subject': subject, 'sender': sender, 'date': date,
        'verdict': verdict, 'verdict_text': verdict_text, 'risk': risk, 'color': color,
        'score': min(score, 100), 'findings': findings if findings else [{'severity': 'INFO', 'category': 'Result', 
                        'description': 'No suspicious indicators detected', 'details': 'Email passed all security checks'}],
        'checks': checks, 'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'version': VER
    }

# ==================== PDF Report Generator ====================
def create_pdf(r):
    if not PDF_OK: raise Exception("PDF library not available")
    path = os.path.join(REPORTS, f"NATIVE_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    doc = SimpleDocTemplate(path, pagesize=A4, title=f"NATIVE Report - {r['file']}")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CustomTitle', parent=styles['Heading1'], fontSize=24, 
                              textColor=colors.HexColor('#2c3e50'), alignment=1, spaceAfter=12, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='CustomSubTitle', parent=styles['Heading2'], fontSize=14, 
                              textColor=colors.HexColor('#7f8c8d'), alignment=1, spaceAfter=20))
    styles.add(ParagraphStyle(name='CustomSection', parent=styles['Heading2'], fontSize=14, 
                              textColor=colors.HexColor('#2c3e50'), spaceAfter=10, spaceBefore=15))
    
    story = []
    story.append(Paragraph("🛡️NATIVE", styles['CustomTitle']))
    story.append(Paragraph("Phishing Email Detection System", styles['CustomSubTitle']))
    story.append(Spacer(1, 20))
    story.append(Paragraph("Executive Summary", styles['CustomSection']))
    if r['verdict'] == "PHISHING":
        story.append(Paragraph("<b>⚠️ ACTION REQUIRED:</b> This email has been identified as a phishing attempt. Do not interact with any links or attachments.", styles['Normal']))
    elif r['verdict'] == "SUSPICIOUS":
        story.append(Paragraph("<b>⚠️ CAUTION:</b> This email contains suspicious elements. Exercise caution before interacting.", styles['Normal']))
    else:
        story.append(Paragraph("<b>✓ CLEAR:</b> No significant phishing indicators were detected in this email.", styles['Normal']))
    story.append(Spacer(1, 20))
    story.append(Paragraph("Analysis Details", styles['CustomSection']))
    data = [['📁 File Name', r['file']], ['📝 Subject', r['subject']], ['👤 Sender', r['sender']],
            ['📅 Date', r['date']], ['🎯 Verdict', r['verdict_text']], ['📊 Risk Score', f"{r['score']}/100"],
            ['⚡ Risk Level', r['risk']], ['🔧 Engine Version', f"v{r['version']}"]]
    t = Table(data, colWidths=[2*72, 4*72])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0,0), (0,-1), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'), ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME', (1,0), (1,-1), 'Helvetica'), ('FONTSIZE', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10), ('TOPPADDING', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (1,4), (1,4), colors.HexColor(r['color'])),
        ('TEXTCOLOR', (1,4), (1,4), colors.white),
    ]))
    story.append(t)
    story.append(Spacer(1, 25))
    story.append(Paragraph("Detection Findings", styles['CustomSection']))
    for i, f in enumerate(r['findings'], 1):
        sev = f.get('severity', 'INFO')
        color = '#c0392b' if sev == 'CRITICAL' else '#e74c3c' if sev == 'HIGH' else '#f39c12' if sev == 'MEDIUM' else '#27ae60'
        icon = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡' if sev == 'MEDIUM' else '🟢'
        story.append(Paragraph(f"<b>{i}.</b> <font color='{color}'>{icon} {f.get('category', '')}</font><br/>"
                              f"<i>{f.get('description', '')}</i><br/>"
                              f"<font color='#7f8c8d'>{f.get('details', '')}</font>", styles['Normal']))
        story.append(Spacer(1, 10))
    story.append(Spacer(1, 15))
    story.append(Paragraph("Security Checks Performed", styles['CustomSection']))
    story.append(Paragraph(f"<i>{', '.join(r.get('checks', []))}</i>", styles['Normal']))
    story.append(Spacer(1, 20))
    story.append(Paragraph("Security Recommendations", styles['CustomSection']))
    if r['verdict'] == "PHISHING":
        recs = ["Do NOT click any links in this email", "Do NOT download or open any attachments",
                "Do NOT reply to this email", "Delete this email immediately",
                "Report to your IT security team", "If you already interacted, change passwords immediately"]
    elif r['verdict'] == "SUSPICIOUS":
        recs = ["Verify the sender's identity through other channels", "Do not share sensitive information",
                "Hover over links before clicking", "When in doubt, delete the email"]
    else:
        recs = ["Continue practicing good security habits", "Verify unexpected requests through official channels"]
    for rec in recs:
        story.append(Paragraph(f"• {rec}", styles['Normal']))
        story.append(Spacer(1, 5))
    story.append(Spacer(1, 30))
    story.append(Paragraph("<i>___________________________________________________</i>", styles['Normal']))
    story.append(Paragraph(f"<i>{APP} v{VER} | Analysis Report | Generated: {r['time']}</i>", styles['Normal']))
    doc.build(story)
    return path

# ==================== GUI Application ====================
class App:
    def __init__(self, root):
        self.root = root
        root.title(f"{APP} v{VER}")
        root.geometry("1000x750")
        root.minsize(950, 700)
        root.configure(bg='#f5f6fa')
        self.result = None
        self._header()
        self._file_section()
        self._analyze_btn()
        self._results()
        self._pdf_btn()
        self._history()
        self._footer()
        if not PDF_OK:
            root.after(1000, lambda: messagebox.showwarning("PDF Library Missing", "PDF reports disabled.\n\nTo enable:\npip install reportlab"))
        log("Application started")
    
    def _header(self):
        h = tk.Frame(self.root, bg='#2c3e50', height=100); h.pack(fill='x'); h.pack_propagate(False)
        tk.Label(h, text=f"🛡️  {APP}", font=('Segoe UI', 24, 'bold'), bg='#2c3e50', fg='white').pack(pady=12)
        tk.Label(h, text="Enterprise Phishing Detection System", font=('Segoe UI', 10), bg='#2c3e50', fg='#bdc3c7').pack()
    
    def _file_section(self):
        f = tk.LabelFrame(self.root, text="📧 Email File Selection", font=('Segoe UI', 10, 'bold'), bg='#f5f6fa', fg='#2c3e50')
        f.pack(fill='x', padx=25, pady=15)
        self.file_var = tk.StringVar()
        tk.Entry(f, textvariable=self.file_var, font=('Segoe UI', 10), bg='white', relief='solid', bd=1).pack(side='left', fill='x', expand=True, padx=10, pady=8)
        tk.Button(f, text="📁 Browse", command=self._browse, font=('Segoe UI', 10, 'bold'), bg='#3498db', fg='white', relief='flat', padx=20).pack(side='right', padx=10, pady=8)
    
    def _analyze_btn(self):
        tk.Button(self.root, text="🔍 Analyze Email", command=self._analyze, font=('Segoe UI', 14, 'bold'), bg='#27ae60', fg='white', relief='flat', padx=45, pady=18).pack(pady=15)
    
    def _results(self):
        f = tk.LabelFrame(self.root, text="📊 Analysis Results", font=('Segoe UI', 10, 'bold'), bg='#f5f6fa', fg='#2c3e50')
        f.pack(fill='both', expand=True, padx=25, pady=10)
        row = tk.Frame(f, bg='#f5f6fa'); row.pack(fill='x', pady=8)
        self.verdict_lbl = tk.Label(row, text="Result: --", font=('Segoe UI', 16, 'bold'), bg='#f5f6fa', fg='#7f8c8d'); self.verdict_lbl.pack(side='left', padx=20)
        self.score_lbl = tk.Label(row, text="Score: --/100", font=('Segoe UI', 16), bg='#f5f6fa', fg='#3498db'); self.score_lbl.pack(side='right', padx=20)
        self.findings_txt = scrolledtext.ScrolledText(f, font=('Consolas', 10), bg='white', relief='solid', bd=1, wrap='word', state='disabled', height=9)
        self.findings_txt.pack(fill='both', expand=True, padx=10, pady=10)
        for tag, color in [('red', '#c0392b'), ('orange', '#e67e22'), ('green', '#27ae60')]: self.findings_txt.tag_configure(tag, foreground=color)
    
    def _pdf_btn(self):
        self.pdf_btn = tk.Button(self.root, text="📄 Generate PDF Report", command=self._export_pdf, state='disabled', font=('Segoe UI', 11, 'bold'), bg='#34495e', fg='white', relief='flat', padx=35, pady=12)
        self.pdf_btn.pack(pady=10)
    
    def _history(self):
        f = tk.LabelFrame(self.root, text="📋 Recent Scans", font=('Segoe UI', 10, 'bold'), bg='#f5f6fa', fg='#2c3e50')
        f.pack(fill='x', padx=25, pady=10)
        self.history = tk.Listbox(f, font=('Segoe UI', 9), bg='white', height=3)
        self.history.pack(fill='x', padx=10, pady=8)
        self.history.insert(0, "👋 Welcome! Select an email file to begin")
        self.history.itemconfig(0, fg='#27ae60')
    
    def _footer(self):
        self.status = tk.StringVar(value=f"Ready | {APP} v{VER} | © 2026")
        tk.Label(self.root, textvariable=self.status, font=('Segoe UI', 9), bg='#2c3e50', fg='white', anchor='w', padx=15, pady=8).pack(fill='x', side='bottom')
    
    def _browse(self):
        path = filedialog.askopenfilename(title="Select Email (.eml)", filetypes=[("Email Files", "*.eml"), ("All Files", "*.*")])
        if path: self.file_var.set(path); self.status.set(f"✓ {os.path.basename(path)}")
    
    def _analyze(self):
        path = self.file_var.get()
        if not path: messagebox.showwarning("Warning", "Please select an email file first"); return
        if not os.path.exists(path): messagebox.showerror("Error", "File not found"); return
        self.status.set("🔄 Analyzing..."); self.root.update()
        try:
            self.result = analyze(path)
            if 'error' in self.result: raise Exception(self.result['error'])
            self._show_results(); self.pdf_btn.config(state='normal'); self._add_history()
            log(f"✓ {self.result['file']} | {self.result['verdict']} | {self.result['score']}/100")
            self.status.set("✓ Analysis Complete")
        except Exception as e: log(f"✗ {str(e)}"); messagebox.showerror("Error", str(e)); self.status.set("✗ Error")
    
    def _show_results(self):
        r = self.result
        self.verdict_lbl.config(text=f"Result: {r['verdict_text']}", fg=r['color'])
        self.score_lbl.config(text=f"Score: {r['score']}/100")
        self.findings_txt.config(state='normal'); self.findings_txt.delete('1.0', tk.END)
        for f in r['findings']:
            sev = f.get('severity', 'INFO')
            tag = 'red' if sev in ['CRITICAL', 'HIGH'] else 'orange' if sev == 'MEDIUM' else 'green'
            self.findings_txt.insert(tk.END, f"📍 {f.get('category', '')}\n", tag)
            self.findings_txt.insert(tk.END, f"   {f.get('description', '')}\n", tag)
            if f.get('details'): self.findings_txt.insert(tk.END, f"   {f.get('details', '')}\n\n", 'green')
            else: self.findings_txt.insert(tk.END, "\n")
        self.findings_txt.config(state='disabled')
    
    def _export_pdf(self):
        if not self.result: return
        if not PDF_OK: messagebox.showerror("Error", "PDF library not installed.\n\nInstall with: pip install reportlab"); return
        try:
            path = create_pdf(self.result)
            messagebox.showinfo("Success", f"✓ PDF Report saved successfully!\n\n📁 Location:\n{path}")
            log(f"📄 PDF: {os.path.basename(path)}"); self.status.set("✓ PDF Saved")
        except Exception as e: messagebox.showerror("Error", f"Failed to generate PDF:\n{str(e)}")
    
    def _add_history(self):
        r = self.result
        icon = '🔴' if r['verdict'] == 'PHISHING' else '🟡' if r['verdict'] == 'SUSPICIOUS' else '🟢'
        entry = f"[{datetime.now().strftime('%H:%M')}] {icon} {r['verdict_text']} - {r['file']}"
        self.history.insert(0, entry); self.history.itemconfig(0, fg=r['color'])
        if self.history.size() > 10: self.history.delete(10)

def main():
    root = tk.Tk()
    app = App(root)
    root.after(500, lambda: messagebox.showinfo(f"Welcome to {APP}", f"{APP} v{VER}\n\nEnterprise Phishing Detection System\n\nQuick Start:\n1. Click Browse → Select .eml file\n2. Click Analyze Email\n3. Review results & save PDF\n\n© 2026 NATIVE Security"))
    root.mainloop()

if __name__ == "__main__":
    main()