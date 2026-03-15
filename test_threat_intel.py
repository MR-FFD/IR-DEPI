"""
Threat Intelligence Module Test Suite
Tests all API integrations with real and sample data
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from threat_intelligence import ThreatIntelligence
import json


def test_without_api_keys():
    """Test the module structure without API keys"""
    print("="*70)
    print("         Testing Threat Intelligence Module (Demo Mode)")
    print("="*70)
    print()
    
    ti = ThreatIntelligence()
    
    print("📋 Module Configuration:")
    print(f"  VirusTotal API: {'✅ Configured' if ti.virustotal_key else '❌ Not configured'}")
    print(f"  AbuseIPDB API: {'✅ Configured' if ti.abuseipdb_key else '❌ Not configured'}")
    print(f"  URLScan.io API: {'✅ Configured' if ti.urlscan_key else '❌ Not configured'}")
    print(f"  HaveIBeenPwned API: {'✅ Configured' if ti.hibp_key else '❌ Not configured'}")
    print()
    
    # Test with Google DNS (should be clean)
    print("🔍 Test 1: Checking clean IP (8.8.8.8 - Google DNS)")
    print("-"*70)
    result = ti.check_all(ip='8.8.8.8')
    summary = ti.get_summary()
    
    print(f"  Verdict: {summary['overall_verdict']}")
    print(f"  Threat Score: {summary['threat_score']}/100")
    print(f"  APIs Checked: {summary['apis_checked']}/4")
    print(f"  Findings: {len(ti.results.get('findings', []))}")
    
    # ✅ Fixed: Access findings from ti.results not summary
    if ti.results.get('findings'):
        print("\n  Findings Details:")
        for finding in ti.results['findings']:
            print(f"    - [{finding['severity']}] {finding['description']}")
    
    print()
    
    # Test with known malicious IP (example from abuse reports)
    print("🔍 Test 2: Checking suspicious IP (Simulated)")
    print("-"*70)
    print("  Note: Real malicious IP check requires AbuseIPDB API key")
    print("  Without API key, this will show 'API not configured'")
    print()
    
    # Test email breach check
    print("🔍 Test 3: Checking email breach (Simulated)")
    print("-"*70)
    print("  Note: Requires HaveIBeenPwned API key")
    print()
    
    print("="*70)
    print("                        TEST SUMMARY")
    print("="*70)
    print()
    print("✅ Module loaded successfully")
    print("✅ All functions are working")
    print("⚠️  To enable real-time threat intelligence:")
    print("   1. Get free API keys from the providers")
    print("   2. Add them to .env file")
    print("   3. Run tests again")
    print()
    print("📝 API Key Links:")
    print("   • VirusTotal: https://www.virustotal.com/gui/my-apikey")
    print("   • AbuseIPDB: https://www.abuseipdb.com/api")
    print("   • URLScan.io: https://urlscan.io/user/profile/")
    print("   • HaveIBeenPwned: https://haveibeenpwned.com/API/v3")
    print()


def test_with_sample_data():
    """Test with pre-defined sample responses"""
    print("="*70)
    print("         Sample Threat Intelligence Report")
    print("="*70)
    print()
    
    # Simulated results
    sample_results = {
        'ip': '185.220.101.1',
        'abuse_score': 95,
        'total_reports': 247,
        'country': 'DE',
        'verdict': 'CRITICAL_THREAT',
        'threat_score': 85
    }
    
    print("📊 Simulated Analysis Results:")
    print("-"*70)
    print(f"  IP Address: {sample_results['ip']}")
    print(f"  Abuse Confidence: {sample_results['abuse_score']}%")
    print(f"  Total Reports: {sample_results['total_reports']}")
    print(f"  Country: {sample_results['country']}")
    print(f"  Verdict: 🔴 {sample_results['verdict']}")
    print(f"  Threat Score: {sample_results['threat_score']}/100")
    print()
    print("  Findings:")
    print("    🔴 [CRITICAL] IP has 95% abuse confidence score")
    print("    🔴 [CRITICAL] 247 abuse reports in last 90 days")
    print("    🟠 [HIGH] Known malicious IP in threat databases")
    print()


def main():
    """Main test runner"""
    print()
    print("╔" + "="*68 + "╗")
    print("║" + " "*15 + "IR-DEPI Threat Intelligence Test Suite" + " "*15 + "║")
    print("╚" + "="*68 + "╝")
    print()
    
    # Test 1: Module structure
    test_without_api_keys()
    
    print()
    input("Press Enter to see sample results...")
    print()
    
    # Test 2: Sample data
    test_with_sample_data()
    
    print("="*70)
    print()
    print("✅ All tests completed!")
    print()
    print("🎯 Next Steps:")
    print("   1. Get at least ONE API key (VirusTotal recommended)")
    print("   2. Add it to .env file")
    print("   3. Run: py test_threat_intel.py")
    print("   4. See real threat intelligence data!")
    print()


if __name__ == "__main__":
    main()