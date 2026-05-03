================================================================
    🛡️ NATIVE | Phishing Email Detection System
    Version 1.0.0 | (c) 2026 NATIVE Security
================================================================

DEPI - Digital Egypt Pioneers Initiative
Ministry of Communications and Information Technology (MCIT)
Track: Incident Response
Developer: MFNN Team

================================================================
⚡ QUICK START
================================================================

For End Users (Using Pre-Built EXE):
------------------------------------
1. Download NATIVE.exe from Releases section
2. Double-click NATIVE.exe
3. Click "Browse" and select an email file (.eml)
4. Click "Analyze Email"
5. Review the results and optionally save PDF report

That's it. No installation needed.

For Users Downloading from Source (GitHub):
-------------------------------------------
1. Download/Clone the repository
2. IMPORTANT: Run build.bat to generate NATIVE.exe
3. After build completes, go to dist/ folder
4. Double-click NATIVE.exe to launch
5. Select .eml file and click "Analyze Email"

NOTE: The EXE file is NOT included in the repository.
      You MUST run build.bat to generate it locally.

For Developers (From Source):
-----------------------------
1. Clone: git clone https://github.com/MR-FFD/IR-DEPI.git
2. Install: pip install reportlab
3. Run: python NATIVE.py
4. Build EXE: build.bat (generates dist/NATIVE.exe)

================================================================
 BUILD INSTRUCTIONS (IMPORTANT!)
================================================================

The repository contains SOURCE CODE only. The executable file
(NATIVE.exe) is NOT included and must be built locally.

Why?
----
- EXE files are large (~18 MB)
- EXE is generated per system architecture
- Building locally ensures compatibility
- Security best practice (verify source before running)

How to Build:
-------------
1. Ensure Python 3.8+ is installed
2. Open Command Prompt or Git Bash in project folder
3. Run: build.bat
4. Wait 1-2 minutes for build to complete
5. Find NATIVE.exe in the dist/ folder
6. Run dist/NATIVE.exe

Build Requirements:
-------------------
- Python 3.8 or higher
- pip (Python package manager)
- Internet connection (for initial library download)

The build.bat script will automatically:
✓ Install required libraries (reportlab, pyinstaller)
✓ Package the application into NATIVE.exe
✓ Create the dist/ folder with the executable

================================================================
✨ FEATURES
================================================================

✅ 7-Layer Phishing Detection Engine
✅ Context-Aware False Positive Reduction (0% FP Rate)
✅ Professional PDF Forensic Reports
✅ 100% Offline Operation - Zero Data Exfiltration
✅ Portable EXE Distribution via PyInstaller
✅ Enterprise-Grade Phishing Database (100+ Patterns)
✅ Real-Time Scan History Tracking
✅ Windows 7/8/10/11 Compatible

================================================================
🔍 DETECTION LAYERS (7 Total)
================================================================

Layer 1: IP-Based URLs          40 pts  CRITICAL
  - Detects raw IP addresses in links
  
Layer 2: Urgency Language       25 pts  HIGH
  - Identifies pressure tactics (urgent, immediately, etc.)
  
Layer 3: Suspicious Domains     15-35 pts  HIGH
  - Flags high-risk TLDs (.xyz, .tk, .ml, .ga, .cf, etc.)
  
Layer 4: Generic Greetings      15 pts  MEDIUM
  - Impersonal salutations (Dear Customer, etc.)
  
Layer 5: Data Requests          30 pts  CRITICAL
  - Sensitive information requests (password, credit card, etc.)
  - Context-Aware: Excludes HR/payroll contexts
  
Layer 6: Brand Impersonation    20 pts  MEDIUM
  - Sender domain vs. claimed brand mismatch
  
Layer 7: URL Shorteners         15 pts  MEDIUM
  - Hidden destination links (bit.ly, tinyurl, etc.)

================================================================
📊 RESULTS EXPLAINED
================================================================

Verdict         Score Range   Color   Action Required
-----------------------------------------------------------------
🟢 Clean        0-14          Green   No action needed
🟡 Suspicious   15-49         Orange  Exercise caution, verify sender
🔴 Phishing     50-100        Red     Delete immediately, report to IT

================================================================
🧪 TEST RESULTS
================================================================

Test Dataset: 8 Sample Emails
- 3 Phishing Emails:  100% Detection Rate (3/3)
- 2 Clean Emails:     100% Accuracy (2/2)
- 3 Suspicious Emails: 100% Detection (3/3)

Overall Accuracy: 100% (8/8)
False Positive Rate: 0%
Average Processing Time: < 2 seconds per email

================================================================
📄 PDF REPORTS
================================================================

Each PDF report includes:
- Executive Summary with verdict-specific recommendations
- Analysis Details table (file, subject, sender, date, verdict, score)
- Detection Findings with severity indicators
- Security Checks Performed list
- Contextual Security Recommendations
- Timestamp and engine version for audit trails

To enable PDF reports:
    pip install reportlab

Without this, scanning still works – just no PDF export.

================================================================
💻 SYSTEM REQUIREMENTS
================================================================

For Running NATIVE.exe:
-----------------------
Operating System:  Windows 7 / 8 / 10 / 11 (64-bit)
RAM:               512 MB minimum (1 GB recommended)
Disk Space:        100 MB free space
Internet:          NOT required (100% offline operation)

For Building EXE (build.bat):
-----------------------------
Python:            3.8 or higher
pip:               Latest version
Internet:          Required (for initial library download)
Disk Space:        200 MB free space

================================================================
📁 PROJECT STRUCTURE
================================================================

IR-DEPI/
    NATIVE.py           - Main application (340 lines)
    build.bat           -  RUN THIS to generate NATIVE.exe
    requirements.txt    - Python dependencies
    README.txt          - This file
    LICENSE             - Commercial license
    .gitignore          - Files to exclude from Git
    samples/            - Test email files (8 .eml files)
        01_clean_welcome.eml
        02_clean_newsletter.eml
        03_suspicious_invoice.eml
        04_suspicious_account.eml
        05_phishing_paypal.eml
        06_phishing_bank.eml
        07_phishing_package.eml
        08_medium_marketing.eml
    dist/               - ⚡ GENERATED AFTER BUILD (contains NATIVE.exe)
    reports/            - Generated PDFs (auto-created after first report)
    native.log          - Activity log (auto-created)

IMPORTANT FILES:
----------------
📄 NATIVE.py    = Source code (Python)
📄 build.bat    = ⚡ BUILD SCRIPT - Run this to create EXE
📁 dist/        = GENERATED FOLDER - Contains NATIVE.exe after build

FILES NOT IN REPOSITORY (Auto-Generated):
-----------------------------------------
❌ dist/NATIVE.exe     - Generated by build.bat
❌ reports/*.pdf       - Generated after first PDF export
❌ native.log          - Generated on first run
❌ build/              - Temporary build files
❌ *.spec              - PyInstaller specification file

================================================================
🐛 TROUBLESHOOTING
================================================================

Q: Where is NATIVE.exe?
A: The EXE is NOT included in the repository.
   You must run build.bat to generate it.
   After build, find it in: dist/NATIVE.exe

Q: build.bat shows an error
A: Ensure Python 3.8+ is installed and added to PATH.
   Run: python --version
   If not recognized, install Python from python.org

Q: Windows Defender shows a warning
A: This is a false positive (common with PyInstaller).
   Right-click NATIVE.exe > Properties > Check "Unblock" > OK

Q: PDF button is disabled
A: Install reportlab: pip install reportlab
   Scanning still works without PDF export.

Q: Scan results seem wrong
A: Review findings manually. Context-aware filtering reduces
   false positives for HR/payroll emails.

Q: EXE not created after build.bat
A: Run: pip install --upgrade pyinstaller
   Then run build.bat again.

Q: Import error when running from source
A: Run: pip install -r requirements.txt

================================================================
🔒 SECURITY & PRIVACY
================================================================

Data Privacy Commitments:
✅ No Data Collection - NATIVE does not send emails anywhere
✅ No Telemetry - Zero usage tracking or analytics
✅ 100% Offline - All analysis happens locally
✅ No Cloud Storage - Reports and logs stay on your device
✅ Open for Audit - Source code available for security review

Security Best Practices:
1. Verify suspicious emails through official channels
2. Delete confirmed phishing emails immediately
3. Report to IT team for organizational accounts
4. Change passwords if you interacted with phishing
5. Keep NATIVE updated for latest detection patterns

================================================================
📊 VERSION HISTORY
================================================================

Version 1.0.0 (May 2026) - Current
----------------------------------
✅ Initial DEPI Release
✅ 7-Layer Detection Engine
✅ Context-Aware Filtering (0% False Positives)
✅ Professional PDF Reports
✅ Portable EXE Distribution
✅ Enterprise Phishing Database (100+ Patterns)

Version 1.1.0 (Q3 2026) - Planned
---------------------------------
📋 Attachment Scanning
📋 Expanded TLD Database
📋 Multi-Language Support

Version 1.2.0 (Q4 2026) - Planned
---------------------------------
📋 Real-Time Email Monitoring
📋 API Integration
📋 Cloud Sync Option

Version 2.0.0 (2027) - Vision
-----------------------------
🚀 Cross-Platform Support (Mac/Linux)
🚀 Machine Learning Integration
🚀 Enterprise Dashboard


================================================================
📜 LICENSE
================================================================

© 2026 NATIVE Security. All Rights Reserved.

This software is provided for legitimate security testing 
and email analysis purposes only.

PERMITTED:
✓ Personal use
✓ Commercial use
✓ Modification for internal use
✓ Distribution of unmodified EXE

PROHIBITED:
✗ Malicious use
✗ Reverse engineering for exploitation
✗ Redistribution of modified source without permission
✗ Integration into malicious tools

DISCLAIMER:
The developers are not responsible for misuse of this tool.
No warranty is provided. Use at your own risk.

================================================================
ATTRIBUTION
================================================================

NATIVE Enterprise v1.0.0
Developer: MFNN Team
Organization: NATIVE Security
Track: Incident Response - Digital Egypt Pioneers Initiative (DEPI)
Ministry: Ministry of Communications and Information Technology (MCIT)
Year: 2026

================================================================
        🛡️ NATIVE Enterprise | Stay Safe. Verify Everything.
================================================================
