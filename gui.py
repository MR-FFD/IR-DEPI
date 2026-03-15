"""IR-DEPI | Enterprise Phishing Detection System - GUI Interface"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import sys
import os
import time
import json
import re
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from src.engine import PhishingEngine
from src.logger import setup_logger

logger = setup_logger("PhishingGUI")


class PhishingDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IR-DEPI | Enterprise Phishing Detection System")
        self.root.geometry("950x750")
        self.root.resizable(False, False)
        
        self.colors = {
            'bg': '#1a1a2e',
            'fg': '#ffffff',
            'accent': '#0f3460',
            'success': '#2ecc71',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'info': '#3498db'
        }
        
        self.root.configure(bg=self.colors['bg'])
        self.last_result = None
        self.db = None
        self.file_path_var = None
        self.attachment_path_var = None
        
        self.create_widgets()
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self.root, bg=self.colors['accent'], height=110)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="IR-DEPI | Phishing Detection System", font=('Segoe UI', 16, 'bold'), bg=self.colors['accent'], fg=self.colors['fg']).pack(pady=(10, 5))
        
        buttons_frame = tk.Frame(header_frame, bg=self.colors['accent'])
        buttons_frame.pack(pady=5)
        
        tk.Button(buttons_frame, text="📊 Analysis History", command=self.show_history, font=('Segoe UI', 10, 'bold'), bg=self.colors['info'], fg=self.colors['fg'], relief='flat', padx=15, pady=8, cursor='hand2', width=18).pack(side='left', padx=10)
        
        tk.Button(buttons_frame, text="📎 Scan Attachment", command=self.scan_attachment, font=('Segoe UI', 10, 'bold'), bg=self.colors['warning'], fg=self.colors['fg'], relief='flat', padx=15, pady=8, cursor='hand2', width=18).pack(side='left', padx=10)
        
        tk.Button(buttons_frame, text="🌐 Threat Intel", command=self.check_threat_intel, font=('Segoe UI', 10, 'bold'), bg=self.colors['danger'], fg=self.colors['fg'], relief='flat', padx=15, pady=8, cursor='hand2', width=18).pack(side='left', padx=10)
        
        # Main Frame
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # File Selection
        file_frame = tk.LabelFrame(main_frame, text=" 📧 Email File Selection ", font=('Segoe UI', 11, 'bold'), bg=self.colors['bg'], fg=self.colors['fg'], padx=15, pady=15)
        file_frame.pack(fill='x', pady=(0, 15))
        
        self.file_path_var = tk.StringVar()
        tk.Entry(file_frame, textvariable=self.file_path_var, font=('Segoe UI', 10), bg='#2c2c3e', fg=self.colors['fg'], relief='flat', highlightthickness=1, highlightbackground=self.colors['accent']).pack(side='left', fill='x', expand=True, padx=(0, 10))
        tk.Button(file_frame, text="Browse", command=self.browse_file, font=('Segoe UI', 10, 'bold'), bg=self.colors['info'], fg=self.colors['fg'], relief='flat', padx=20, pady=8, cursor='hand2').pack(side='right')
        
        # Attachment Selection
        attachment_frame = tk.LabelFrame(main_frame, text=" 📎 Attachment Analysis (Optional) ", font=('Segoe UI', 11, 'bold'), bg=self.colors['bg'], fg=self.colors['fg'], padx=15, pady=15)
        attachment_frame.pack(fill='x', pady=(0, 15))
        
        self.attachment_path_var = tk.StringVar()
        tk.Entry(attachment_frame, textvariable=self.attachment_path_var, font=('Segoe UI', 10), bg='#2c2c3e', fg=self.colors['fg'], relief='flat', highlightthickness=1, highlightbackground=self.colors['accent']).pack(side='left', fill='x', expand=True, padx=(0, 10))
        tk.Button(attachment_frame, text="Select File", command=self.browse_attachment, font=('Segoe UI', 10, 'bold'), bg=self.colors['warning'], fg=self.colors['fg'], relief='flat', padx=15, pady=8, cursor='hand2').pack(side='right')
        
        # Analyze Button
        tk.Button(main_frame, text="🔍 ANALYZE EMAIL", command=self.analyze_email, font=('Segoe UI', 12, 'bold'), bg=self.colors['success'], fg=self.colors['fg'], relief='flat', padx=30, pady=12, cursor='hand2').pack(pady=(0, 15), fill='x')
        
        # Results Frame
        results_frame = tk.LabelFrame(main_frame, text=" 📊 Analysis Results ", font=('Segoe UI', 11, 'bold'), bg=self.colors['bg'], fg=self.colors['fg'], padx=15, pady=15)
        results_frame.pack(fill='both', expand=True)
        
        verdict_frame = tk.Frame(results_frame, bg=self.colors['bg'])
        verdict_frame.pack(fill='x', pady=(0, 10))
        
        self.verdict_label = tk.Label(verdict_frame, text="Verdict: --", font=('Segoe UI', 14, 'bold'), bg=self.colors['bg'], fg=self.colors['fg'])
        self.verdict_label.pack(side='left')
        
        self.score_label = tk.Label(verdict_frame, text="Score: --/100", font=('Segoe UI', 14, 'bold'), bg=self.colors['bg'], fg=self.colors['info'])
        self.score_label.pack(side='right')
        
        self.findings_text = ScrolledText(results_frame, font=('Consolas', 10), bg='#2c2c3e', fg=self.colors['fg'], relief='flat', wrap='word', height=10)
        self.findings_text.pack(fill='both', expand=True)
        
        self.findings_text.tag_configure('critical', foreground=self.colors['danger'])
        self.findings_text.tag_configure('high', foreground='#e67e22')
        self.findings_text.tag_configure('medium', foreground=self.colors['warning'])
        self.findings_text.tag_configure('low', foreground=self.colors['success'])
        self.findings_text.tag_configure('info', foreground=self.colors['info'])
        
        self.export_btn = tk.Button(results_frame, text="📄 Export PDF Report", command=self.export_pdf, font=('Segoe UI', 10, 'bold'), bg=self.colors['accent'], fg=self.colors['fg'], relief='flat', padx=20, pady=10, cursor='hand2', state='disabled')
        self.export_btn.pack(pady=(10, 0))
        
        # Status Bar
        status_frame = tk.Frame(self.root, bg=self.colors['accent'], height=35)
        status_frame.pack(fill='x', side='bottom')
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="Ready | IR-DEPI v2.0.0", font=('Segoe UI', 9), bg=self.colors['accent'], fg=self.colors['fg'])
        self.status_label.pack(pady=8)
        
    def browse_file(self):
        filename = filedialog.askopenfilename(title="Select Email File", filetypes=[("Email Files", "*.eml"), ("All Files", "*.*")], initialdir=os.path.expanduser("~"))
        if filename:
            self.file_path_var.set(filename)
            self.status_label.config(text=f"Selected: {os.path.basename(filename)}")
    
    def browse_attachment(self):
        filename = filedialog.askopenfilename(title="Select Attachment File", filetypes=[("All Files", "*.*")], initialdir=os.path.expanduser("~"))
        if filename:
            self.attachment_path_var.set(filename)
            self.status_label.config(text=f"Attachment: {os.path.basename(filename)}")
    
    def analyze_email(self):
        file_path = self.file_path_var.get()
        
        if not file_path:
            messagebox.showwarning("Warning", "Please select an email file first!")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found!")
            return
        
        self.status_label.config(text="Analyzing...")
        self.root.update()
        
        start_time = time.time()
        
        try:
            engine = PhishingEngine()
            if not engine.load_email(file_path):
                messagebox.showerror("Error", "Failed to load email file!")
                return
            
            result = engine.run_analysis()
            
            # Attachment Analysis
            attachment_path = self.attachment_path_var.get()
            if attachment_path and os.path.exists(attachment_path):
                from attachment_scanner import AttachmentScanner
                scanner = AttachmentScanner()
                att_result = scanner.scan_file(attachment_path)
                if 'findings' not in result:
                    result['findings'] = []
                result['findings'].extend(att_result.get('findings', []))
                if att_result.get('score', 0) > 0:
                    result['score'] = result.get('score', 0) + att_result['score']
                    if result['score'] >= 50:
                        result['verdict'] = 'PHISHING_DETECTED'
                result['attachment_analyzed'] = True
            
            # Threat Intelligence
            try:
                from threat_intelligence import ThreatIntelligence
                ti = ThreatIntelligence()
                metadata = result.get('metadata', {})
                email_from = metadata.get('from', '')
                
                ip_to_check = None
                for finding in result.get('findings', []):
                    evidence = finding.get('evidence', '')
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', evidence):
                        ip_to_check = evidence
                        break
                
                ti_result = ti.check_all(ip=ip_to_check)
                result['threat_intel'] = {
                    'verdict': ti_result.get('verdict', 'NO_THREAT'),
                    'threat_score': ti_result.get('threat_score', 0),
                    'virustotal': ti_result.get('virustotal'),
                    'abuseipdb': ti_result.get('abuseipdb'),
                    'findings': ti_result.get('findings', [])
                }
                
                if ti_result.get('verdict') in ['CRITICAL_THREAT', 'HIGH_THREAT']:
                    if result.get('score', 0) < 50:
                        result['score'] = max(result['score'], ti_result['threat_score'])
                    if result['score'] >= 50:
                        result['verdict'] = 'PHISHING_DETECTED'
            except Exception as e:
                logger.error(f"Threat Intelligence error: {e}")
            
            self.last_result = result
            
            # Save to Database
            try:
                from database import PhishingDatabase
                db = PhishingDatabase()
                db.save_analysis(result, file_path, time.time() - start_time)
            except Exception as e:
                logger.error(f"Database save error: {e}")
            
            self.display_results(result)
            self.export_btn.config(state='normal')
            self.status_label.config(text=f"Complete | {result['verdict']}")
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
            self.status_label.config(text="Error during analysis")
    
    def display_results(self, result):
        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('score', 0)
        
        if verdict == "PHISHING_DETECTED":
            self.verdict_label.config(text="Verdict: PHISHING", fg=self.colors['danger'])
        elif verdict == "SUSPICIOUS":
            self.verdict_label.config(text="Verdict: SUSPICIOUS", fg=self.colors['warning'])
        else:
            self.verdict_label.config(text="Verdict: CLEAN", fg=self.colors['success'])
        
        self.score_label.config(text=f"Score: {score}/100")
        self.findings_text.delete('1.0', tk.END)
        
        findings = result.get('findings', [])
        
        if findings:
            self.findings_text.insert(tk.END, f"FINDINGS ({len(findings)}):\n\n", 'info')
            for i, f in enumerate(findings, 1):
                sev = f.get('severity', 'INFO')
                tag = sev.lower()
                self.findings_text.insert(tk.END, f"{i}. [{sev}] {f.get('category', 'Unknown')}\n", tag)
                self.findings_text.insert(tk.END, f"    {f.get('description', 'N/A')}\n\n", 'info')
        else:
            self.findings_text.insert(tk.END, "No suspicious indicators found!\n", 'success')
        
        # Threat Intelligence Section
        if result.get('threat_intel'):
            ti = result['threat_intel']
            self.findings_text.insert(tk.END, "\n" + "="*50 + "\n", 'info')
            self.findings_text.insert(tk.END, "🌐 THREAT INTELLIGENCE RESULTS\n", 'info')
            self.findings_text.insert(tk.END, "="*50 + "\n\n", 'info')
            
            ti_verdict = ti.get('verdict', 'UNKNOWN')
            ti_score = ti.get('threat_score', 0)
            
            if ti_verdict == 'CRITICAL_THREAT':
                self.findings_text.insert(tk.END, f"🔴 Overall: {ti_verdict} (Score: {ti_score}/100)\n\n", 'critical')
            elif ti_verdict == 'HIGH_THREAT':
                self.findings_text.insert(tk.END, f"🟠 Overall: {ti_verdict} (Score: {ti_score}/100)\n\n", 'high')
            else:
                self.findings_text.insert(tk.END, f"🟢 Overall: {ti_verdict} (Score: {ti_score}/100)\n\n", 'success')
            
            if ti.get('abuseipdb'):
                ab = ti['abuseipdb']
                score_ab = ab.get('abuse_score', 0)
                status = "🔴 HIGH RISK" if score_ab >= 50 else "🟡 MEDIUM" if score_ab > 0 else "🟢 CLEAN"
                color = 'critical' if score_ab >= 50 else 'medium' if score_ab > 0 else 'success'
                self.findings_text.insert(tk.END, f"  • AbuseIPDB: {status}\n", color)
                self.findings_text.insert(tk.END, f"    └─ Abuse Score: {score_ab}%\n", 'info')
            
            if ti.get('virustotal'):
                vt = ti['virustotal']
                status = "🔴 MALICIOUS" if vt.get('malicious', 0) > 0 else "🟢 CLEAN"
                self.findings_text.insert(tk.END, f"  • VirusTotal: {status}\n", 'critical' if vt.get('malicious', 0) > 0 else 'success')
                self.findings_text.insert(tk.END, f"    └─ Malicious: {vt.get('malicious', 0)} engines\n", 'info')
            
            self.findings_text.insert(tk.END, "\n", 'info')
        
        if result.get('attachment_analyzed'):
            self.findings_text.insert(tk.END, "\n" + "="*50 + "\n", 'info')
            self.findings_text.insert(tk.END, "📎 Attachment was also analyzed\n", 'info')
    
    def export_pdf(self):
        if self.last_result is None:
            messagebox.showwarning("Warning", "No results to export!")
            return
        
        try:
            from report_generator import PDFReportGenerator
            generator = PDFReportGenerator()
            filepath = generator.generate(self.last_result, self.file_path_var.get())
            messagebox.showinfo("Success", f"PDF saved:\n{filepath}")
            self.status_label.config(text=f"PDF Exported")
        except Exception as e:
            logger.error(f"PDF error: {e}")
            messagebox.showerror("Error", f"PDF export failed: {str(e)}")
    
    def show_history(self):
        try:
            from database import PhishingDatabase
            self.db = PhishingDatabase()
            
            history_win = tk.Toplevel(self.root)
            history_win.title("Analysis History")
            history_win.geometry("1000x700")
            history_win.configure(bg=self.colors['bg'])
            
            tk.Label(history_win, text="Analysis History Database", font=('Segoe UI', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(pady=10)
            
            stats_frame = tk.Frame(history_win, bg=self.colors['accent'], height=100)
            stats_frame.pack(fill='x', padx=10, pady=10)
            stats_frame.pack_propagate(False)
            
            stats = self.db.get_statistics()
            stats_labels = [f"Total: {stats['total_analyses']}", f"Phishing: {stats['phishing_detected']}", f"Suspicious: {stats['suspicious']}", f"Clean: {stats['clean']}", f"Avg Score: {stats['average_score']}"]
            
            for stat_text in stats_labels:
                tk.Label(stats_frame, text=stat_text, font=('Segoe UI', 11, 'bold'), bg=self.colors['accent'], fg=self.colors['fg']).pack(side='left', padx=15, pady=10)
            
            search_frame = tk.Frame(history_win, bg=self.colors['bg'])
            search_frame.pack(fill='x', padx=10, pady=10)
            
            search_var = tk.StringVar()
            tk.Entry(search_frame, textvariable=search_var, font=('Segoe UI', 10), bg='#2c2c3e', fg=self.colors['fg'], relief='flat', highlightthickness=1, highlightbackground=self.colors['accent']).pack(side='left', fill='x', expand=True, padx=(0, 10))
            
            tk.Button(search_frame, text="Search", command=lambda: self.search_history(search_var.get(), history_list), font=('Segoe UI', 10, 'bold'), bg=self.colors['info'], fg=self.colors['fg'], relief='flat', padx=15, cursor='hand2').pack(side='left')
            tk.Button(search_frame, text="Refresh", command=lambda: self.load_history(history_list), font=('Segoe UI', 10, 'bold'), bg=self.colors['success'], fg=self.colors['fg'], relief='flat', padx=15, cursor='hand2').pack(side='left', padx=5)
            
            list_frame = tk.Frame(history_win, bg=self.colors['bg'])
            list_frame.pack(fill='both', expand=True, padx=10, pady=10)
            
            scrollbar = tk.Scrollbar(list_frame)
            scrollbar.pack(side='right', fill='y')
            
            history_list = tk.Listbox(list_frame, font=('Consolas', 9), bg='#2c2c3e', fg=self.colors['fg'], selectbackground=self.colors['accent'], yscrollcommand=scrollbar.set, height=20)
            history_list.pack(side='left', fill='both', expand=True)
            scrollbar.config(command=history_list.yview)
            
            self.load_history(history_list)
            history_list.bind('<Double-Button-1>', lambda e: self.view_analysis_details(history_list))
            
        except Exception as e:
            logger.error(f"Error showing history: {e}")
            messagebox.showerror("Error", f"Failed to load history: {str(e)}")
    
    def load_history(self, listbox):
        try:
            from database import PhishingDatabase
            db = PhishingDatabase()
            analyses = db.get_all_analyses(100)
            
            listbox.delete(0, tk.END)
            
            for analysis in analyses:
                timestamp = analysis['timestamp'][:16].replace('T', ' ')
                verdict = analysis['verdict']
                score = analysis['risk_score']
                subject = analysis['email_subject'][:40]
                
                if verdict == 'PHISHING_DETECTED':
                    color = '#e74c3c'
                    icon = '[PHISH]'
                elif verdict == 'SUSPICIOUS':
                    color = '#f39c12'
                    icon = '[SUSP]'
                else:
                    color = '#2ecc71'
                    icon = '[OK]'
                
                listbox.insert(tk.END, f"{icon} [{timestamp}] {verdict} ({score}) - {subject}")
                last_idx = listbox.size() - 1
                listbox.itemconfig(last_idx, fg=color)
                
        except Exception as e:
            logger.error(f"Error loading history: {e}")
    
    def search_history(self, keyword, listbox):
        try:
            from database import PhishingDatabase
            db = PhishingDatabase()
            results = db.search_analyses(keyword)
            
            listbox.delete(0, tk.END)
            
            for analysis in results:
                timestamp = analysis['timestamp'][:16].replace('T', ' ')
                verdict = analysis['verdict']
                score = analysis['risk_score']
                subject = analysis['email_subject'][:40]
                
                if verdict == 'PHISHING_DETECTED':
                    color = '#e74c3c'
                    icon = '[PHISH]'
                elif verdict == 'SUSPICIOUS':
                    color = '#f39c12'
                    icon = '[SUSP]'
                else:
                    color = '#2ecc71'
                    icon = '[OK]'
                
                listbox.insert(tk.END, f"{icon} [{timestamp}] {verdict} ({score}) - {subject}")
                last_idx = listbox.size() - 1
                listbox.itemconfig(last_idx, fg=color)
                
        except Exception as e:
            messagebox.showerror("Error", f"Search failed: {str(e)}")
    
    def view_analysis_details(self, listbox):
        try:
            selection = listbox.curselection()
            if not selection:
                return
            
            from database import PhishingDatabase
            db = PhishingDatabase()
            analyses = db.get_all_analyses(100)
            
            idx = selection[0]
            analysis = analyses[idx]
            
            details_win = tk.Toplevel(self.root)
            details_win.title("Analysis Details")
            details_win.geometry("600x500")
            details_win.configure(bg=self.colors['bg'])
            
            tk.Label(details_win, text="Analysis Details", font=('Segoe UI', 14, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(pady=10)
            
            details_text = tk.Text(details_win, font=('Consolas', 9), bg='#2c2c3e', fg=self.colors['fg'], relief='flat', wrap='word', padx=10, pady=10)
            details_text.pack(fill='both', expand=True, padx=10, pady=10)
            
            details_text.insert(tk.END, f"Timestamp: {analysis['timestamp']}\n")
            details_text.insert(tk.END, f"From: {analysis['email_from']}\n")
            details_text.insert(tk.END, f"To: {analysis['email_to']}\n")
            details_text.insert(tk.END, f"Subject: {analysis['email_subject']}\n")
            details_text.insert(tk.END, f"Verdict: {analysis['verdict']}\n")
            details_text.insert(tk.END, f"Risk Score: {analysis['risk_score']}/100\n")
            details_text.insert(tk.END, f"Findings: {analysis['findings_count']}\n")
            details_text.insert(tk.END, f"File: {analysis['file_path']}\n")
            
            if analysis['findings_json']:
                findings = json.loads(analysis['findings_json'])
                details_text.insert(tk.END, "\n--- Findings ---\n")
                for i, f in enumerate(findings, 1):
                    details_text.insert(tk.END, f"{i}. [{f['severity']}] {f['category']}: {f['description']}\n")
            
            details_text.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load details: {str(e)}")
    
    def scan_attachment(self):
        file_path = filedialog.askopenfilename(title="Select File to Scan", filetypes=[("All Files", "*.*")], initialdir=os.path.expanduser("~"))
        
        if not file_path:
            return
        
        self.status_label.config(text="Scanning attachment...")
        self.root.update()
        
        try:
            from attachment_scanner import AttachmentScanner
            scanner = AttachmentScanner()
            result = scanner.scan_file(file_path)
            
            msg = f"Attachment Scan Results\n{'='*40}\n\n"
            msg += f"File: {os.path.basename(file_path)}\n"
            msg += f"Risk Score: {result['score']}\n\n"
            
            if result['findings']:
                msg += "Findings:\n"
                for i, finding in enumerate(result['findings'], 1):
                    msg += f"{i}. [{finding['severity']}] {finding['description']}\n"
            else:
                msg += "No suspicious indicators found."
            
            messagebox.showinfo("Attachment Scan", msg)
            self.status_label.config(text="Attachment scan complete")
            
        except Exception as e:
            messagebox.showerror("Error", f"Scan failed: {str(e)}")
            self.status_label.config(text="Scan error")
    
    def check_threat_intel(self):
        intel_win = tk.Toplevel(self.root)
        intel_win.title("Threat Intelligence Check")
        intel_win.geometry("500x400")
        intel_win.configure(bg=self.colors['bg'])
        
        tk.Label(intel_win, text="🌐 Check IP / URL / Hash", font=('Segoe UI', 14, 'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(pady=10)
        
        input_frame = tk.Frame(intel_win, bg=self.colors['bg'])
        input_frame.pack(pady=10)
        
        tk.Label(input_frame, text="Enter IP, URL, or File Hash:", font=('Segoe UI', 10), bg=self.colors['bg'], fg=self.colors['fg']).pack()
        
        input_var = tk.StringVar()
        tk.Entry(input_frame, textvariable=input_var, font=('Segoe UI', 10), bg='#2c2c3e', fg=self.colors['fg'], width=50).pack(pady=5)
        
        result_text = ScrolledText(intel_win, font=('Consolas', 9), bg='#2c2c3e', fg=self.colors['fg'], height=15, state='disabled')
        result_text.pack(pady=10, padx=10, fill='both', expand=True)
        
        def run_check():
            value = input_var.get().strip()
            if not value:
                messagebox.showwarning("Warning", "Please enter a value!")
                return
            
            result_text.config(state='normal')
            result_text.delete('1.0', tk.END)
            result_text.insert(tk.END, f"🔍 Checking: {value}\n\n")
            intel_win.update()
            
            try:
                from threat_intelligence import ThreatIntelligence
                
                ti = ThreatIntelligence()
                
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
                    result = ti.check_all(ip=value)
                elif value.startswith('http'):
                    result = ti.check_all(url=value)
                elif len(value) == 64 and all(c in '0123456789abcdef' for c in value.lower()):
                    result = ti.check_all(file_hash=value)
                else:
                    result_text.insert(tk.END, "⚠️ Could not determine input type.\n")
                    result_text.insert(tk.END, "Supported: IP address, URL, or SHA256 hash\n")
                    result_text.config(state='disabled')
                    return
                
                summary = ti.get_summary()
                result_text.insert(tk.END, f"Verdict: {summary['overall_verdict']}\n")
                result_text.insert(tk.END, f"Threat Score: {summary['threat_score']}/100\n")
                result_text.insert(tk.END, f"APIs Checked: {summary['apis_checked']}/3\n\n")
                
                if ti.results.get('findings'):
                    result_text.insert(tk.END, "Findings:\n")
                    for f in ti.results['findings']:
                        result_text.insert(tk.END, f"  • [{f['severity']}] {f['description']}\n")
                else:
                    result_text.insert(tk.END, "✅ No threats detected\n")
                
            except Exception as e:
                result_text.insert(tk.END, f"❌ Error: {str(e)}\n")
            
            result_text.config(state='disabled')
        
        tk.Button(intel_win, text="Check Now", command=run_check, font=('Segoe UI', 10, 'bold'), bg=self.colors['success'], fg=self.colors['fg'], relief='flat', padx=20, pady=8, cursor='hand2').pack(pady=10)


def main():
    root = tk.Tk()
    app = PhishingDetectorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()