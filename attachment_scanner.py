"""
Enterprise Attachment Scanner Module for IR-DEPI
Advanced file analysis including Magic Bytes, Macro Detection, and more
"""

import os
import hashlib
import json
import zipfile
import olefile
import pdfplumber
from typing import Dict, List, Any, Optional
from datetime import datetime
from src.logger import setup_logger

logger = setup_logger("AttachmentScanner")


class AttachmentScanner:
    """Enterprise-grade attachment scanner with multiple detection layers"""
    
    # Magic Bytes Signatures
    MAGIC_SIGNATURES = {
        'exe': [b'MZ', b'PE\x00\x00'],
        'dll': [b'MZ'],
        'pdf': [b'%PDF'],
        'zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
        'rar': [b'Rar!\x1a\x07', b'Rar!\x1a\x07\x00'],
        'doc': [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'],
        'docx': [b'PK\x03\x04'],
        'xls': [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'],
        'xlsx': [b'PK\x03\x04'],
        'ppt': [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'],
        'pptx': [b'PK\x03\x04'],
        'jpg': [b'\xFF\xD8\xFF'],
        'png': [b'\x89PNG\r\n\x1a\n'],
        'gif': [b'GIF87a', b'GIF89a'],
        'js': [b'//', b'/*', b'var ', b'function'],
        'vbs': [b"'", b'Rem ', b'Dim ', b'Set '],
        'ps1': [b'#', b'param(', b'function '],
        'lnk': [b'\x4C\x00\x00\x00\x01\x14\x02\x00'],
    }
    
    # Dangerous file types
    DANGEROUS_EXTENSIONS = [
        '.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', 
        '.jar', '.msi', '.com', '.pif', '.application', '.gadget',
        '.reg', '.msc', '.msu', '.ps1xml', '.scf', '.lnk'
    ]
    
    # Suspicious file types
    SUSPICIOUS_EXTENSIONS = [
        '.zip', '.rar', '.7z', '.tar', '.gz',
        '.doc', '.docm', '.dot', '.dotm',
        '.xls', '.xlsm', '.xlt', '.xltm',
        '.ppt', '.pptm', '.pot', '.potm',
        '.pdf', '.rtf', '.hta', '.wsf', '.wsc'
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.virustotal_api_key = self.config.get('virustotal_api_key', None)
        self.results = {
            'score': 0,
            'findings': [],
            'file_info': {},
            'scan_time': datetime.now().isoformat()
        }
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Complete file scan with all detection layers"""
        self.results = {
            'score': 0,
            'findings': [],
            'file_info': {},
            'scan_time': datetime.now().isoformat()
        }
        
        try:
            if not os.path.exists(file_path):
                self._add_finding('ERROR', 'File', 'File not found', file_path)
                return self.results
            
            # Layer 1: Basic File Info
            self._analyze_file_info(file_path)
            
            # Layer 2: Magic Bytes Analysis
            self._analyze_magic_bytes(file_path)
            
            # Layer 3: Extension Analysis
            self._analyze_extension(file_path)
            
            # Layer 4: File Size Analysis
            self._analyze_file_size(file_path)
            
            # Layer 5: Double Extension Check
            self._check_double_extension(file_path)
            
            # Layer 6: Macro Detection (Office files)
            self._detect_macros(file_path)
            
            # Layer 7: PDF Analysis
            self._analyze_pdf(file_path)
            
            # Layer 8: Archive Analysis
            self._analyze_archive(file_path)
            
            # Layer 9: Hash Calculation
            self._calculate_hashes(file_path)
            
            # Layer 10: VirusTotal Check (if API key available)
            if self.virustotal_api_key:
                self._check_virustotal(file_path)
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            self._add_finding('ERROR', 'Scanner', f'Scan failed: {str(e)}', '')
        
        return self.results
    
    def _add_finding(self, severity: str, category: str, description: str, evidence: str):
        """Add a finding to results"""
        self.results['findings'].append({
            'severity': severity,
            'category': category,
            'description': description,
            'evidence': evidence
        })
        
        # Score calculation
        score_map = {
            'CRITICAL': 50,
            'HIGH': 30,
            'MEDIUM': 15,
            'LOW': 5,
            'INFO': 0,
            'ERROR': 0
        }
        self.results['score'] += score_map.get(severity, 0)
    
    def _analyze_file_info(self, file_path: str):
        """Analyze basic file information"""
        try:
            stat = os.stat(file_path)
            self.results['file_info'] = {
                'path': file_path,
                'name': os.path.basename(file_path),
                'size': stat.st_size,
                'size_human': self._human_readable_size(stat.st_size),
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'extension': os.path.splitext(file_path)[1].lower()
            }
        except Exception as e:
            logger.error(f"File info error: {e}")
    
    def _human_readable_size(self, size: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    def _analyze_magic_bytes(self, file_path: str):
        """Analyze file magic bytes/signatures"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            extension = os.path.splitext(file_path)[1].lower().lstrip('.')
            detected_type = None
            
            for file_type, signatures in self.MAGIC_SIGNATURES.items():
                for sig in signatures:
                    if header.startswith(sig):
                        detected_type = file_type
                        break
                if detected_type:
                    break
            
            # Check for mismatch
            if detected_type and detected_type != extension:
                self._add_finding(
                    'CRITICAL',
                    'File Signature',
                    f'File signature mismatch! Extension: .{extension}, Actual: {detected_type}',
                    f'Header: {header[:8].hex()}'
                )
            else:
                self._add_finding(
                    'INFO',
                    'File Signature',
                    f'File signature verified: {detected_type or "Unknown"}',
                    f'Header: {header[:8].hex()}'
                )
                
        except Exception as e:
            logger.error(f"Magic bytes error: {e}")
    
    def _analyze_extension(self, file_path: str):
        """Analyze file extension for threats"""
        extension = os.path.splitext(file_path)[1].lower()
        
        if extension in self.DANGEROUS_EXTENSIONS:
            self._add_finding(
                'CRITICAL',
                'File Type',
                f'Dangerous file type detected: {extension}',
                os.path.basename(file_path)
            )
        elif extension in self.SUSPICIOUS_EXTENSIONS:
            self._add_finding(
                'MEDIUM',
                'File Type',
                f'Suspicious file type: {extension}',
                os.path.basename(file_path)
            )
    
    def _analyze_file_size(self, file_path: str):
        """Analyze file size for anomalies"""
        try:
            size = os.path.getsize(file_path)
            
            if size == 0:
                self._add_finding(
                    'MEDIUM',
                    'File Size',
                    'Empty file detected',
                    f'{size} bytes'
                )
            elif size > 50 * 1024 * 1024:  # 50MB
                self._add_finding(
                    'LOW',
                    'File Size',
                    'Unusually large file',
                    self._human_readable_size(size)
                )
            elif size < 100 and size > 0:
                self._add_finding(
                    'LOW',
                    'File Size',
                    'Very small file (potential dropper)',
                    self._human_readable_size(size)
                )
        except Exception as e:
            logger.error(f"File size error: {e}")
    
    def _check_double_extension(self, file_path: str):
        """Check for double file extensions"""
        filename = os.path.basename(file_path)
        name_without_ext = os.path.splitext(filename)[0]
        
        if '.' in name_without_ext:
            # Get last two extensions
            parts = filename.split('.')
            if len(parts) >= 3:
                ext1 = '.' + parts[-1]
                ext2 = '.' + parts[-2]
                
                if ext1 in self.DANGEROUS_EXTENSIONS or ext1 in self.SUSPICIOUS_EXTENSIONS:
                    self._add_finding(
                        'HIGH',
                        'File Name',
                        f'Double extension detected (potential evasion)',
                        f'{ext2}{ext1}'
                    )
    
    def _detect_macros(self, file_path: str):
        """Detect VBA Macros in Office files"""
        extension = os.path.splitext(file_path)[1].lower()
        
        if extension in ['.doc', '.docm', '.dot', '.dotm', '.xls', '.xlsm', 
                         '.xlt', '.xltm', '.ppt', '.pptm', '.pot', '.potm']:
            try:
                if olefile.isOleFile(file_path):
                    ole = olefile.OleFileIO(file_path)
                    
                    # Check for VBA macros
                    has_macros = False
                    macro_streams = []
                    
                    for stream in ole.listdir():
                        stream_name = '/'.join(stream)
                        if 'VBA' in stream_name or 'Macros' in stream_name:
                            has_macros = True
                            macro_streams.append(stream_name)
                    
                    if has_macros:
                        self._add_finding(
                            'HIGH',
                            'Macro',
                            f'VBA Macros detected in Office file',
                            f'Streams: {", ".join(macro_streams[:3])}'
                        )
                    
                    ole.close()
                else:
                    self._add_finding(
                        'INFO',
                        'File Format',
                        'Not an OLE file (may be OOXML)',
                        os.path.basename(file_path)
                    )
                    
            except Exception as e:
                logger.error(f"Macro detection error: {e}")
    
    def _analyze_pdf(self, file_path: str):
        """Analyze PDF for malicious content"""
        extension = os.path.splitext(file_path)[1].lower()
        
        if extension == '.pdf':
            try:
                with pdfplumber.open(file_path) as pdf:
                    # Check for JavaScript
                    has_js = False
                    js_count = 0
                    
                    for page in pdf.pages:
                        if page.get('js'):
                            has_js = True
                            js_count += 1
                    
                    # Check metadata
                    metadata = pdf.metadata
                    suspicious_metadata = False
                    
                    if metadata:
                        if metadata.get('/Producer', '').lower() in ['microsoft', 'word']:
                            suspicious_metadata = True
                            self._add_finding(
                                'MEDIUM',
                                'PDF',
                                'PDF created from Office document (potential conversion)',
                                f'Producer: {metadata.get("/Producer", "N/A")}'
                            )
                    
                    if has_js:
                        self._add_finding(
                            'CRITICAL',
                            'PDF',
                            f'JavaScript detected in PDF ({js_count} occurrences)',
                            'Embedded JS code'
                        )
                    
                    # Check for embedded files
                    if pdf.embedded_files:
                        self._add_finding(
                            'HIGH',
                            'PDF',
                            f'Embedded files detected in PDF',
                            f'Count: {len(pdf.embedded_files)}'
                        )
                        
            except Exception as e:
                logger.error(f"PDF analysis error: {e}")
    
    def _analyze_archive(self, file_path: str):
        """Analyze archive files for malicious content"""
        extension = os.path.splitext(file_path)[1].lower()
        
        if extension in ['.zip', '.rar', '.7z', '.tar', '.gz']:
            try:
                if extension == '.zip':
                    with zipfile.ZipFile(file_path, 'r') as zip_file:
                        # Check for password protection
                        is_password_protected = False
                        for info in zip_file.infolist():
                            if info.flag_bits & 0x1:
                                is_password_protected = True
                                break
                        
                        if is_password_protected:
                            self._add_finding(
                                'HIGH',
                                'Archive',
                                'Password-protected archive detected',
                                'May contain hidden malicious content'
                            )
                        
                        # Check file count
                        file_count = len(zip_file.infolist())
                        if file_count > 100:
                            self._add_finding(
                                'LOW',
                                'Archive',
                                'Large number of files in archive',
                                f'File count: {file_count}'
                            )
                        
                        # Check for dangerous files inside
                        dangerous_inside = []
                        for info in zip_file.infolist():
                            for ext in self.DANGEROUS_EXTENSIONS:
                                if info.filename.lower().endswith(ext):
                                    dangerous_inside.append(info.filename)
                        
                        if dangerous_inside:
                            self._add_finding(
                                'CRITICAL',
                                'Archive',
                                f'Dangerous files inside archive',
                                f'Files: {", ".join(dangerous_inside[:5])}'
                            )
                            
            except Exception as e:
                logger.error(f"Archive analysis error: {e}")
    
    def _calculate_hashes(self, file_path: str):
        """Calculate file hashes for identification"""
        try:
            hashes = {
                'md5': self._calculate_hash(file_path, 'md5'),
                'sha1': self._calculate_hash(file_path, 'sha1'),
                'sha256': self._calculate_hash(file_path, 'sha256')
            }
            
            self.results['file_info']['hashes'] = hashes
            
            self._add_finding(
                'INFO',
                'File Hash',
                'File hashes calculated',
                f'SHA256: {hashes["sha256"][:32]}...'
            )
            
        except Exception as e:
            logger.error(f"Hash calculation error: {e}")
    
    def _calculate_hash(self, file_path: str, algorithm: str) -> str:
        """Calculate file hash with specified algorithm"""
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    
    def _check_virustotal(self, file_path: str):
        """Check file hash against VirusTotal API"""
        try:
            import requests
            
            file_hash = self.results['file_info'].get('hashes', {}).get('sha256', '')
            
            if not file_hash:
                return
            
            # Check hash report
            url = 'https://www.virustotal.com/api/v3/files/{hash}'
            headers = {
                'x-apikey': self.virustotal_api_key
            }
            
            response = requests.get(url.format(hash=file_hash), headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                if malicious > 0:
                    self._add_finding(
                        'CRITICAL',
                        'VirusTotal',
                        f'File detected as malicious by {malicious} engines',
                        f'Malicious: {malicious}, Suspicious: {suspicious}'
                    )
                elif suspicious > 0:
                    self._add_finding(
                        'HIGH',
                        'VirusTotal',
                        f'File flagged as suspicious by {suspicious} engines',
                        f'Suspicious: {suspicious}'
                    )
                else:
                    self._add_finding(
                        'INFO',
                        'VirusTotal',
                        'No threats detected by VirusTotal',
                        f'Clean'
                    )
                    
        except Exception as e:
            logger.error(f"VirusTotal check error: {e}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary"""
        return {
            'total_findings': len(self.results['findings']),
            'critical': sum(1 for f in self.results['findings'] if f['severity'] == 'CRITICAL'),
            'high': sum(1 for f in self.results['findings'] if f['severity'] == 'HIGH'),
            'medium': sum(1 for f in self.results['findings'] if f['severity'] == 'MEDIUM'),
            'low': sum(1 for f in self.results['findings'] if f['severity'] == 'LOW'),
            'info': sum(1 for f in self.results['findings'] if f['severity'] == 'INFO'),
            'total_score': self.results['score'],
            'file_info': self.results['file_info'],
            'scan_time': self.results['scan_time']
        }


# Test function
if __name__ == "__main__":
    scanner = AttachmentScanner()
    
    # Test with a sample file
    import sys
    if len(sys.argv) > 1:
        result = scanner.scan_file(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python attachment_scanner.py <file_path>")