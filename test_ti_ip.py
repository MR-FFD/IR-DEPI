"""Test Threat Intelligence with EICAR Test File Hash"""

from threat_intelligence import ThreatIntelligence

print("="*60)
print("    Testing File Hash: EICAR Test File")
print("="*60)
print()

# EICAR test file SHA256 hash (standard test file)
eicar_hash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

ti = ThreatIntelligence()
result = ti.check_all(file_hash=eicar_hash)
summary = ti.get_summary()

print(f"Verdict: {summary['overall_verdict']}")
print(f"Threat Score: {summary['threat_score']}/100")
print(f"APIs Checked: {summary['apis_checked']}/3")
print()

if ti.results.get('virustotal'):
    vt = ti.results['virustotal']
    print(f"VirusTotal Results:")
    print(f"  • Malicious: {vt.get('malicious', 0)} engines")
    print(f"  • Suspicious: {vt.get('suspicious', 0)} engines")
    print(f"  • Harmless: {vt.get('harmless', 0)} engines")
print()

if ti.results.get('findings'):
    print("Findings:")
    for f in ti.results['findings']:
        print(f"  • [{f['severity']}] {f['description']}")
print()

if summary['threat_score'] > 0:
    print("✅ TEST PASSED: Malicious file hash correctly detected!")
else:
    print("⚠️ TEST WARNING: No threats detected for known malware hash")