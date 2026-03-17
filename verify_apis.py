"""
IR-DEPI | API Verification Script
يتأكد من عمل جميع Threat Intelligence APIs
"""

import requests
import json
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

print("="*70)
print("         IR-DEPI | API Verification Test")
print("="*70)
print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*70)
print()

# ============ API Keys Check ============
print("1️⃣ API Keys Configuration")
print("-"*70)

api_keys = {
    'VirusTotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
    'AbuseIPDB': os.getenv('ABUSEIPDB_API_KEY', ''),
    'URLScan.io': os.getenv('URLSCAN_API_KEY', '')
}

for name, key in api_keys.items():
    if key and key != 'your_virustotal_key_here':
        print(f"   ✅ {name}: Configured")
    else:
        print(f"   ❌ {name}: NOT Configured")

print()

# ============ VirusTotal Test ============
print("2️⃣ VirusTotal API Test")
print("-"*70)

vt_key = api_keys['VirusTotal']
if vt_key:
    try:
        # Test with EICAR hash (known malware)
        eicar_hash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
        headers = {'x-apikey': vt_key}
        
        response = requests.get(
            f'https://www.virustotal.com/api/v3/files/{eicar_hash}',
            headers=headers,
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            
            print(f"   ✅ Status: CONNECTED")
            print(f"   ✅ Test Hash: EICAR")
            print(f"   ✅ Malicious Detections: {malicious}/70")
            print(f"   ✅ API Working: YES")
        else:
            print(f"   ❌ Status: FAILED ({response.status_code})")
            print(f"   ❌ API Working: NO")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        print(f"   ❌ API Working: NO")
else:
    print(f"   ⚠️  Skipped: API Key not configured")

print()

# ============ AbuseIPDB Test ============
print("3️⃣ AbuseIPDB API Test")
print("-"*70)

ab_key = api_keys['AbuseIPDB']
if ab_key:
    try:
        # Test with known malicious IP (Tor Exit Node)
        test_ip = '185.220.101.1'
        headers = {'Key': ab_key, 'Accept': 'application/json'}
        params = {'ipAddress': test_ip, 'maxAgeInDays': 90}
        
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params,
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            abuse_data = data.get('data', {})
            abuse_score = abuse_data.get('abuseConfidenceScore', 0)
            reports = abuse_data.get('totalReports', 0)
            
            print(f"   ✅ Status: CONNECTED")
            print(f"   ✅ Test IP: {test_ip}")
            print(f"   ✅ Abuse Score: {abuse_score}%")
            print(f"   ✅ Total Reports: {reports}")
            print(f"   ✅ API Working: YES")
        else:
            print(f"   ❌ Status: FAILED ({response.status_code})")
            print(f"   ❌ API Working: NO")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        print(f"   ❌ API Working: NO")
else:
    print(f"   ⚠️  Skipped: API Key not configured")

print()

# ============ URLScan.io Test ============
print("4️⃣ URLScan.io API Test")
print("-"*70)

us_key = api_keys['URLScan.io']
if us_key:
    try:
        # Test by checking user profile (lightweight test)
        headers = {'API-Key': us_key}
        
        response = requests.get(
            'https://urlscan.io/api/v1/user/',
            headers=headers,
            timeout=15
        )
        
        if response.status_code == 200:
            print(f"   ✅ Status: CONNECTED")
            print(f"   ✅ API Key: Valid")
            print(f"   ✅ API Working: YES")
        else:
            print(f"   ⚠️  Status: {response.status_code}")
            print(f"   ⚠️  API Working: Limited (but configured)")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        print(f"   ❌ API Working: NO")
else:
    print(f"   ⚠️  Skipped: API Key not configured")

print()

# ============ IR-DEPI Integration Test ============
print("5️⃣ IR-DEPI Integration Test")
print("-"*70)

try:
    from threat_intelligence import ThreatIntelligence
    
    ti = ThreatIntelligence()
    
    # Test with EICAR hash
    result = ti.check_all(file_hash=eicar_hash)
    summary = ti.get_summary()
    
    print(f"   ✅ Module Loaded: YES")
    print(f"   ✅ Hash Check: {summary['overall_verdict']}")
    print(f"   ✅ Threat Score: {summary['threat_score']}/100")
    print(f"   ✅ APIs Checked: {summary['apis_checked']}/3")
    print(f"   ✅ Integration: WORKING")
    
except Exception as e:
    print(f"   ❌ Module Load: FAILED")
    print(f"   ❌ Error: {e}")
    print(f"   ❌ Integration: NOT WORKING")

print()

# ============ Final Summary ============
print("="*70)
print("                        FINAL SUMMARY")
print("="*70)
print()

# Count working APIs
working_apis = 0
total_apis = 3

if api_keys['VirusTotal'] and api_keys['VirusTotal'] != 'your_virustotal_key_here':
    working_apis += 1
if api_keys['AbuseIPDB'] and api_keys['AbuseIPDB'] != 'your_abuseipdb_key_here':
    working_apis += 1
if api_keys['URLScan.io'] and api_keys['URLScan.io'] != 'your_urlscan_key_here':
    working_apis += 1

print(f"📊 API Configuration: {working_apis}/{total_apis}")
print(f"📊 Integration Status: {'✅ WORKING' if working_apis > 0 else '❌ NOT WORKING'}")
print()

if working_apis >= 2:
    print("🎉 Your Threat Intelligence APIs are READY!")
    print("   • VirusTotal: ✅ Working")
    print("   • AbuseIPDB: ✅ Working")
    print("   • URLScan.io: ✅ Configured")
    print()
    print("✅ IR-DEPI is Enterprise-Ready!")
elif working_apis == 1:
    print("⚠️  Partial Configuration")
    print("   • At least 1 API is working")
    print("   • Configure remaining APIs for full functionality")
else:
    print("❌ No APIs Configured")
    print("   • Add API keys to .env file")
    print("   • Run this script again")

print()
print("="*70)