import sys, argparse
from src.engine import PhishingEngine

def main():
    parser = argparse.ArgumentParser(description="Phishing Detector")
    parser.add_argument("email_file", help="Path to .eml file")
    args = parser.parse_args()
    
    engine = PhishingEngine()
    if not engine.load_email(args.email_file):
        print("Error loading file")
        sys.exit(2)
    
    result = engine.run_analysis()
    print(f"\n🔍 VERDICT: {result['verdict']}")
    print(f"📊 Score: {result['score']}")
    for f in result['findings']:
        print(f"  - [{f['severity']}] {f['description']}")
    
    sys.exit(0 if result['verdict'] == 'CLEAN' else 1)

if __name__ == "__main__":
    main()