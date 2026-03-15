import email, re, yaml, tldextract
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from src.logger import setup_logger

logger = setup_logger("PhishingEngine")

class PhishingFinding:
    def __init__(self, category: str, severity: str, description: str, score: int, evidence: str = None):
        self.category, self.severity, self.description, self.score, self.evidence = category, severity, description, score, evidence
    def to_dict(self) -> Dict[str, Any]:
        return {"category": self.category, "severity": self.severity, "description": self.description, "score": self.score, "evidence": self.evidence}

class PhishingEngine:
    def __init__(self, config_path: str = "config/rules.yaml"):
        self.config = self._load_config(config_path)
        self.findings, self.total_score, self.msg, self.metadata = [], 0, None, {}

    def _load_config(self, path: str) -> Dict:
        with open(path, 'r', encoding='utf-8') as f: return yaml.safe_load(f)

    def load_email(self, file_path: str) -> bool:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: self.msg = email.message_from_file(f)
            self.metadata = {"subject": self.msg.get('Subject',''), "from": self.msg.get('From','')}
            return True
        except: return False

    def _add_finding(self, cat, sev, desc, score, evi=None):
        self.findings.append(PhishingFinding(cat, sev, desc, score, evi))
        self.total_score += score

    def analyze_sender(self):
        if not self.msg: return
        from_h, subj = self.msg.get('From',''), self.msg.get('Subject','')
        ext = tldextract.extract(from_h)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        if any(fp in from_h.lower() for fp in self.config['indicators']['free_providers']) and any(b.lower() in subj.lower() for b in self.config['indicators']['legitimate_brands']):
            self._add_finding("Sender", "HIGH", "Free email used for brand", 30, from_h)

    def analyze_links(self):
        if not self.msg: return
        body = ""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() in ["text/plain","text/html"]:
                    try: body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except: pass
        else:
            try: body = self.msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except: pass
        urls = re.findall(r'http[s]?://[^\s"<\')>]+', body)
        for url in urls:
            parsed = urlparse(url)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
                self._add_finding("Link", "CRITICAL", "IP address in link", 40, url)
            if any(url.endswith(tld) for tld in self.config['indicators']['suspicious_tlds']):
                self._add_finding("Link", "MEDIUM", "Suspicious TLD", 15, url)

    def analyze_content(self):
        if not self.msg: return
        text = (self.msg.get('Subject','') + str(self.msg.get_payload())).lower()
        matches = [k for k in self.config['indicators']['urgency_keywords'] if k in text]
        if len(matches) >= 2: self._add_finding("Content", "HIGH", f"Urgency keywords: {len(matches)}", 20, ", ".join(matches))

    def run_analysis(self) -> Dict[str, Any]:
        self.analyze_sender(); self.analyze_links(); self.analyze_content()
        verdict = "PHISHING" if self.total_score >= 50 else "SUSPICIOUS" if self.total_score >= 20 else "CLEAN"
        return {"verdict": verdict, "score": self.total_score, "findings": [f.to_dict() for f in self.findings]}