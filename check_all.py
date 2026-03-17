"""IR-DEPI | Comprehensive System Check"""

import os
import sys
from pathlib import Path

print("="*60)
print("         IR-DEPI | System Health Check")
print("="*60)
print()

checks = {
    'Files': [
        ('gui.py', 'GUI Interface'),
        ('auth.py', 'Authentication'),
        ('database.py', 'Database'),
        ('threat_intelligence.py', 'Threat Intel'),
        ('attachment_scanner.py', 'Attachment Scanner'),
        ('Dockerfile', 'Docker Config'),
        ('docker-compose.yml', 'Docker Compose'),
        ('README.md', 'Documentation'),
        ('.env', 'Environment Config'),
    ],
    'Directories': [
        ('data/', 'Database Storage'),
        ('logs/', 'Log Files'),
        ('reports/', 'PDF Reports'),
        ('samples/', 'Sample Emails'),
    ],
    'APIs': [
        ('VIRUSTOTAL_API_KEY', 'VirusTotal'),
        ('ABUSEIPDB_API_KEY', 'AbuseIPDB'),
        ('URLSCAN_API_KEY', 'URLScan.io'),
        ('JWT_SECRET', 'JWT Secret'),
    ]
}

from dotenv import load_dotenv
load_dotenv()

# Check Files
print("📁 Files:")
for file, desc in checks['Files']:
    status = '✅' if Path(file).exists() else '❌'
    print(f"  {status} {desc} ({file})")

print()

# Check Directories
print("📂 Directories:")
for dir, desc in checks['Directories']:
    status = '✅' if Path(dir).exists() else '❌'
    print(f"  {status} {desc} ({dir})")

print()

# Check APIs
print("🔑 API Configuration:")
for key, desc in checks['APIs']:
    status = '✅' if os.getenv(key) else '❌'
    print(f"  {status} {desc}")

print()
print("="*60)
print("✅ System Check Complete!")
print("="*60)