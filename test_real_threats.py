"""
Real Threat Intelligence Test
Tests with actual API calls using your configured keys
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from threat_intelligence import ThreatIntelligence


def test_real_data():
    """Test with real API calls"""
    print("="*70)
    print("         IR-DEPI | Real Threat Intelligence Test")
    print("="*70)
    print()
    
    ti = ThreatIntelligence()
    
    # Test 1: Clean IP (Google DNS)
    print("🔍 Test 1: Clean IP - 8.8.8.8 (Google DNS)")
    print("-"*70)
    result = ti.check_all(ip='8.8.8.8')
    summary = ti.get_summary()
    
    print(f"  Verdict: {summary['overall_verdict']}")
    print(f"  Threat Score: {summary['threat_score']}/100")
    print(f"  APIs Checked: {summary['apis_checked']}/4")
    
    if ti.results.get('findings'):
        print(f"  Findings: {len(ti.results['findings'])}")
        for f in ti.results['findings']:
            print(f"    - [{f['severity']}] {f['description']}")
    else:
        print("  ✅ No threats detected - IP is clean!")
    print()
    
    # Test 2: Known malicious IP (Tor exit node - example)
    print("🔍 Test 2: Suspicious IP - 185.220.101.1 (Tor Exit Node)")
    print("-"*70)
    print("  Note: This may take 10-30 seconds for API response...")
    result2 = ti.check_all(ip='185.220.101.1')
    summary2 = ti.get_summary()
    
    print(f"  Verdict: {summary2['overall_verdict']}")
    print(f"  Threat Score: {summary2['threat_score']}/100")
    
    if ti.results.get('findings'):
        print(f"  Findings: {len(ti.results['findings'])}")
        for f in ti.results['findings'][-3:]:  # Show last 3
            print(f"    - [{f['severity']}] {f['description']}")
    print()
    
    # Test 3: File hash (Example: EICAR test file hash)
    print("🔍 Test 3: File Hash Check (EICAR Test File)")
    print("-"*70)
    eicar_hash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
    result3 = ti.check_all(file_hash=eicar_hash)
    summary3 = ti.get_summary()
    
    print(f"  Verdict: {summary3['overall_verdict']}")
    print(f"  Threat Score: {summary3['threat_score']}/100")
    
    if ti.results.get('virustotal'):
        vt = ti.results['virustotal']
        print(f"  VirusTotal Results:")
        print(f"    - Malicious: {vt['malicious']}")
        print(f"    - Suspicious: {vt['suspicious']}")
        print(f"    - Harmless: {vt['harmless']}")
    print()
    
    print("="*70)
    print("                        FINAL SUMMARY")
    print("="*70)
    print()
    print("✅ Real API calls completed successfully!")
    print()
    if summary['apis_checked'] > 0 or summary2['apis_checked'] > 0:
        print("🎉 Your API keys are working! Real threat data is now available.")
    else:
        print("⚠️  APIs returned 0 checks - verify your API keys are active.")
    print()


if __name__ == "__main__":
    test_real_data()