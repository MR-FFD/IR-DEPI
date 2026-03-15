"""
Enterprise Threat Intelligence Module for IR-DEPI
Integrates with multiple threat intelligence APIs for real-world data
"""

import os
import requests
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime
from dotenv import load_dotenv
from src.logger import setup_logger

# Load environment variables
load_dotenv()

logger = setup_logger("ThreatIntelligence")


class ThreatIntelligence:
    """Enterprise threat intelligence integration"""
    
    def __init__(self):
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY', '')
        self.urlscan_key = os.getenv('URLSCAN_API_KEY', '')
        self.hibp_key = os.getenv('HIBP_API_KEY', '')
        
        self.results = {
            'virustotal': None,
            'abuseipdb': None,
            'urlscan': None,
            'hibp': None,
            'threat_score': 0,
            'findings': []
        }
    
    def check_all(self, ip: str = None, url: str = None, 
                  file_hash: str = None, email: str = None) -> Dict[str, Any]:
        """Run all available threat intelligence checks"""
        self.results = {
            'virustotal': None,
            'abuseipdb': None,
            'urlscan': None,
            'hibp': None,
            'threat_score': 0,
            'findings': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Check IP reputation
        if ip:
            self.check_ip_reputation(ip)
        
        # Check URL reputation
        if url:
            self.check_url_reputation(url)
        
        # Check file hash
        if file_hash:
            self.check_file_hash(file_hash)
        
        # Check email breach
        if email:
            self.check_email_breach(email)
        
        # Calculate overall threat score
        self._calculate_threat_score()
        
        return self.results
    
    def check_ip_reputation(self, ip: str):
        """Check IP reputation using AbuseIPDB"""
        try:
            if not self.abuseipdb_key:
                logger.warning("AbuseIPDB API key not configured")
                return
            
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                abuse_data = data.get('data', {})
                
                abuse_score = abuse_data.get('abuseConfidenceScore', 0)
                total_reports = abuse_data.get('totalReports', 0)
                is_whitelisted = abuse_data.get('isWhitelisted', False)
                
                self.results['abuseipdb'] = {
                    'ip': ip,
                    'abuse_score': abuse_score,
                    'total_reports': total_reports,
                    'is_whitelisted': is_whitelisted,
                    'country': abuse_data.get('countryCode', 'N/A'),
                    'isp': abuse_data.get('isp', 'N/A')
                }
                
                # Add findings
                if abuse_score >= 80:
                    self.results['findings'].append({
                        'severity': 'CRITICAL',
                        'source': 'AbuseIPDB',
                        'description': f'IP has {abuse_score}% abuse confidence score',
                        'evidence': f'{total_reports} reports from {abuse_data.get("countryCode", "N/A")}'
                    })
                    self.results['threat_score'] += 40
                elif abuse_score >= 50:
                    self.results['findings'].append({
                        'severity': 'HIGH',
                        'source': 'AbuseIPDB',
                        'description': f'IP has {abuse_score}% abuse confidence score',
                        'evidence': f'{total_reports} reports'
                    })
                    self.results['threat_score'] += 25
                elif abuse_score > 0:
                    self.results['findings'].append({
                        'severity': 'MEDIUM',
                        'source': 'AbuseIPDB',
                        'description': f'IP has {abuse_score}% abuse confidence score',
                        'evidence': f'{total_reports} reports'
                    })
                    self.results['threat_score'] += 10
                    
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
            self.results['findings'].append({
                'severity': 'ERROR',
                'source': 'AbuseIPDB',
                'description': f'Check failed: {str(e)}',
                'evidence': ''
            })
    
    def check_url_reputation(self, url: str):
        """Check URL reputation using URLScan.io"""
        try:
            if not self.urlscan_key:
                logger.warning("URLScan.io API key not configured")
                return
            
            # Submit URL for scanning
            submit_url = 'https://urlscan.io/api/v1/scan/'
            headers = {
                'API-Key': self.urlscan_key,
                'Content-Type': 'application/json'
            }
            data = {
                'url': url,
                'visibility': 'private',
                'tags': ['phishing-analysis']
            }
            
            response = requests.post(submit_url, headers=headers, json=data, timeout=10)
            
            if response.status_code == 200:
                scan_data = response.json()
                scan_id = scan_data.get('uuid', '')
                
                # Get scan results
                result_url = f'https://urlscan.io/api/v1/result/{scan_id}/'
                result_response = requests.get(result_url, timeout=10)
                
                if result_response.status_code == 200:
                    result_data = result_response.json()
                    
                    verdict = result_data.get('verdict', {})
                    overall_score = verdict.get('score', 0)
                    categories = verdict.get('categories', [])
                    brands = verdict.get('brands', [])
                    
                    self.results['urlscan'] = {
                        'url': url,
                        'scan_id': scan_id,
                        'overall_score': overall_score,
                        'categories': categories,
                        'brands': brands,
                        'is_malicious': overall_score < 50
                    }
                    
                    # Add findings
                    if overall_score < 30:
                        self.results['findings'].append({
                            'severity': 'CRITICAL',
                            'source': 'URLScan.io',
                            'description': f'URL flagged as malicious (score: {overall_score})',
                            'evidence': f'Categories: {", ".join(categories[:3])}'
                        })
                        self.results['threat_score'] += 40
                    elif overall_score < 60:
                        self.results['findings'].append({
                            'severity': 'HIGH',
                            'source': 'URLScan.io',
                            'description': f'URL flagged as suspicious (score: {overall_score})',
                            'evidence': f'Categories: {", ".join(categories[:3])}'
                        })
                        self.results['threat_score'] += 25
                        
        except Exception as e:
            logger.error(f"URLScan.io check failed: {e}")
    
    def check_file_hash(self, file_hash: str):
        """Check file hash using VirusTotal"""
        try:
            if not self.virustotal_key:
                logger.warning("VirusTotal API key not configured")
                return
            
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {
                'x-apikey': self.virustotal_key
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis = attributes.get('last_analysis_stats', {})
                
                malicious = last_analysis.get('malicious', 0)
                suspicious = last_analysis.get('suspicious', 0)
                harmless = last_analysis.get('harmless', 0)
                
                self.results['virustotal'] = {
                    'hash': file_hash,
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'harmless': harmless,
                    'total_engines': sum(last_analysis.values())
                }
                
                # Add findings
                if malicious >= 5:
                    self.results['findings'].append({
                        'severity': 'CRITICAL',
                        'source': 'VirusTotal',
                        'description': f'File detected as malicious by {malicious} engines',
                        'evidence': f'Malicious: {malicious}, Suspicious: {suspicious}'
                    })
                    self.results['threat_score'] += 50
                elif malicious >= 1:
                    self.results['findings'].append({
                        'severity': 'HIGH',
                        'source': 'VirusTotal',
                        'description': f'File detected as malicious by {malicious} engines',
                        'evidence': f'Malicious: {malicious}, Suspicious: {suspicious}'
                    })
                    self.results['threat_score'] += 30
                elif suspicious >= 3:
                    self.results['findings'].append({
                        'severity': 'MEDIUM',
                        'source': 'VirusTotal',
                        'description': f'File flagged as suspicious by {suspicious} engines',
                        'evidence': f'Suspicious: {suspicious}'
                    })
                    self.results['threat_score'] += 15
                    
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
    
    def check_email_breach(self, email: str):
        """Check if email was in known breaches using HaveIBeenPwned"""
        try:
            if not self.hibp_key:
                logger.warning("HaveIBeenPwned API key not configured")
                return
            
            url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
            headers = {
                'hibp-api-key': self.hibp_key,
                'User-Agent': 'IR-DEPI-Enterprise'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                breaches = response.json()
                
                self.results['hibp'] = {
                    'email': email,
                    'breached': True,
                    'breach_count': len(breaches),
                    'breaches': [b.get('Name', 'N/A') for b in breaches[:5]]
                }
                
                self.results['findings'].append({
                    'severity': 'HIGH',
                    'source': 'HaveIBeenPwned',
                    'description': f'Email found in {len(breaches)} known data breaches',
                    'evidence': f'Breaches: {", ".join(self.results["hibp"]["breaches"])}'
                })
                self.results['threat_score'] += 20
                
            elif response.status_code == 404:
                self.results['hibp'] = {
                    'email': email,
                    'breached': False,
                    'breach_count': 0,
                    'breaches': []
                }
                    
        except Exception as e:
            logger.error(f"HaveIBeenPwned check failed: {e}")
    
    def _calculate_threat_score(self):
        """Calculate overall threat intelligence score"""
        # Already calculated in individual checks
        # Cap at 100
        self.results['threat_score'] = min(100, self.results['threat_score'])
        
        # Add overall verdict
        if self.results['threat_score'] >= 70:
            self.results['verdict'] = 'CRITICAL_THREAT'
        elif self.results['threat_score'] >= 40:
            self.results['verdict'] = 'HIGH_THREAT'
        elif self.results['threat_score'] >= 20:
            self.results['verdict'] = 'MEDIUM_THREAT'
        elif self.results['threat_score'] > 0:
            self.results['verdict'] = 'LOW_THREAT'
        else:
            self.results['verdict'] = 'NO_THREAT'
    
    def get_summary(self) -> Dict[str, Any]:
        """Get threat intelligence summary"""
        return {
            'overall_verdict': self.results.get('verdict', 'UNKNOWN'),
            'threat_score': self.results['threat_score'],
            'total_findings': len(self.results['findings']),
            'critical_findings': sum(1 for f in self.results['findings'] if f['severity'] == 'CRITICAL'),
            'apis_checked': sum([
                1 if self.results['virustotal'] else 0,
                1 if self.results['abuseipdb'] else 0,
                1 if self.results['urlscan'] else 0,
                1 if self.results['hibp'] else 0
            ]),
            'timestamp': self.results.get('timestamp', '')
        }


# Test function
if __name__ == "__main__":
    ti = ThreatIntelligence()
    
    # Test with sample data
    print("Testing Threat Intelligence Module...")
    print("="*60)
    
    # Check a known malicious IP (example)
    result = ti.check_all(ip='8.8.8.8')  # Google DNS (should be clean)
    print(f"IP Check Result: {ti.get_summary()}")
    
    print("\n✅ Threat Intelligence Module Ready!")
    print("\n📝 To enable full functionality:")
    print("1. Get API keys from the providers")
    print("2. Add them to .env file")
    print("3. Run analysis with real data")