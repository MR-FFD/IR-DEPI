import requests
import json

# Your VirusTotal API Key (free tier)
API_KEY = '85af910a3ed3a2142449ff4c79c8f782e7855e7031422cb986c087e35f9f4823'
headers = {'x-apikey': API_KEY}

# Test with known suspicious patterns (SAFE - won't resolve)
test_urls = [
    'http://paypa1-secure.xyz/login',
    'http://microsoft-verify.tk/update',
    'http://192.168.100.55/paypal-login',
    'http://amazon-account.ml/verify',
]

print("="*70)
print("         IR-DEPI | VirusTotal URL Check (Free Tier)")
print("="*70)
print()

for url in test_urls:
    print(f"🔍 Checking: {url}")
    
    try:
        # Submit URL for analysis
        submit_response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers=headers,
            data={'url': url},
            timeout=30
        )
        
        if submit_response.status_code == 200:
            data = submit_response.json()
            analysis_id = data['data']['id']
            
            # Get analysis results
            analysis_response = requests.get(
                f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                headers=headers,
                timeout=30
            )
            
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                stats = analysis_data['data']['attributes']['stats']
                
                print(f"  Malicious: {stats.get('malicious', 0)}/70")
                print(f"  Suspicious: {stats.get('suspicious', 0)}/70")
                print(f"  Clean: {stats.get('harmless', 0)}/70")
            else:
                print(f"  Analysis error: {analysis_response.status_code}")
        else:
            print(f"  Submit error: {submit_response.status_code}")
    
    except Exception as e:
        print(f"  Exception: {e}")
    
    print()