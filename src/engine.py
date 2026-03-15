import email, re, yaml, tldextract
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from src.logger import setup_logger

logger = setup_logger("PhishingEngine")

class PhishingFinding:
    def __init__(self, category: str, severity: str, description: str, score: int, evidence: str = None):
        self.category = category
        self.severity = severity
        self.description = description
        self.score = score
        self.evidence = evidence
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "score": self.score,
            "evidence": self.evidence
        }

class PhishingEngine:
    def __init__(self, config_path: str = "config/rules.yaml"):
        self.config = self._load_config(config_path)
        self.findings = []
        self.total_score = 0
        self.msg = None
        self.metadata = {}

    def _load_config(self, path: str) -> Dict:
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def load_email(self, file_path: str) -> bool:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.msg = email.message_from_file(f)
            self.metadata = {
                "subject": self.msg.get('Subject', ''),
                "from": self.msg.get('From', ''),
                "to": self.msg.get('To', '')
            }
            return True
        except Exception as e:
            logger.error(f"Error loading email: {e}")
            return False

    def _add_finding(self, category, severity, description, score, evidence=None):
        self.findings.append(PhishingFinding(category, severity, description, score, evidence))
        self.total_score += score

    def analyze_sender(self):
        if not self.msg:
            return
        from_header = self.msg.get('From', '')
        subject = self.msg.get('Subject', '')
        
        # Check free provider with brand
        is_free = any(fp in from_header.lower() for fp in self.config['indicators']['free_providers'])
        brand_mentioned = any(b.lower() in subject.lower() for b in self.config['indicators']['legitimate_brands'])
        
        if is_free and brand_mentioned:
            self._add_finding("Sender", "HIGH", "Free email provider used for brand", 30, from_header)

    def analyze_links(self):
        if not self.msg:
            return
        
        body = ""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                body = self.msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                pass
        
        urls = re.findall(r'http[s]?://[^\s"<\')>]+', body)
        
        for url in urls:
            parsed = urlparse(url)
            
            # Check IP address
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
                self._add_finding("Link", "CRITICAL", "IP address in link", 40, url)
            
            # Check suspicious TLD
            if any(url.endswith(tld) for tld in self.config['indicators']['suspicious_tlds']):
                self._add_finding("Link", "MEDIUM", "Suspicious TLD", 15, url)

    def analyze_content(self):
        if not self.msg:
            return
        
        text = (self.msg.get('Subject', '') + str(self.msg.get_payload())).lower()
        keywords = self.config['indicators']['urgency_keywords']
        matches = [k for k in keywords if k in text]
        
        if len(matches) >= 2:
            self._add_finding("Content", "HIGH", f"Urgency keywords: {len(matches)}", 20, ", ".join(matches[:3]))
        elif len(matches) > 0:
            self._add_finding("Content", "LOW", f"Urgency keywords: {len(matches)}", 5, ", ".join(matches))

    def run_analysis(self) -> Dict[str, Any]:
        self.analyze_sender()
        self.analyze_links()
        self.analyze_content()
        
        # ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅
        # LOGIC الصحيح - مغير هنا!
        if self.total_score >= 50:
            verdict = "PHISHING_DETECTED"
        elif self.total_score >= 20:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"
        # ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅ ✅
        
        return {
            "verdict": verdict,
            "score": self.total_score,
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.findings]
        }