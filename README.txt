================================================================
    NATIVE | Phishing Email Detection System
    Version 1.0.0 | (c) 2026 NATIVE Security
================================================================

QUICK START
----------------------------------------------------------------
1. Double-click NATIVE.exe
2. Click "Browse" and select an email file (.eml)
3. Click "Analyze Email"
4. Review the results

That's it. No installation needed.


FEATURES
----------------------------------------------------------------
- 5-layer phishing detection
- Risk scoring (0-100)
- PDF report generation
- Scan history tracking
- Works offline
- Portable (runs from USB)


DETECTION CHECKS
----------------------------------------------------------------
1. IP-based URLs in links
2. Urgency/pressure language
3. Suspicious domain extensions
4. Generic impersonal greetings
5. Requests for sensitive information


RESULTS EXPLAINED
----------------------------------------------------------------
[GREEN]  Clean       (0-19)   - No threats detected
[YELLOW] Suspicious  (20-49)  - Some concerning elements
[RED]    Phishing    (50-100) - High confidence threat


PDF REPORTS
----------------------------------------------------------------
To enable PDF reports, install Python and run:
    pip install reportlab

Without this, scanning still works – just no PDF export.


SYSTEM REQUIREMENTS
----------------------------------------------------------------
- Windows 7 / 8 / 10 / 11
- 512 MB RAM
- 50 MB free disk space
- No internet required


TROUBLESHOOTING
----------------------------------------------------------------
Q: Windows Defender shows a warning
A: This is a false positive. Right-click NATIVE.exe > Properties
   > Check "Unblock" > OK

Q: PDF button is disabled
A: Install reportlab: pip install reportlab

Q: Scan results seem wrong
A: No system is perfect. Review findings manually.


FILE STRUCTURE
----------------------------------------------------------------
NATIVE_Distribution/
    NATIVE.exe          - Main application
    README.txt          - This file
    samples/
        phishing_sample.eml  - Test email
    reports/            - PDF reports (auto-created)


SUPPORT
----------------------------------------------------------------
Developer: MFNN Team
Version: 1.0.0
Year: 2026


LEGAL NOTICE
----------------------------------------------------------------
This tool is for legitimate security testing only.
The developers are not responsible for misuse.

(c) 2026 NATIVE Security. All Rights Reserved.

================================================================
        Stay Safe. Verify Everything.
================================================================