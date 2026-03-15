"""
Attachment Scanner Test Suite
Tests all detection layers of the attachment scanner
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from attachment_scanner import AttachmentScanner

def create_test_files():
    """Create safe test files for scanning"""
    test_dir = Path("test_attachments")
    test_dir.mkdir(exist_ok=True)
    
    files_created = []
    
    # 1. Safe text file
    txt_file = test_dir / "safe_file.txt"
    txt_file.write_text("This is a safe test file for scanning.")
    files_created.append(("Safe Text File", str(txt_file), "CLEAN"))
    
    # 2. BAT file (dangerous extension)
    bat_file = test_dir / "test.bat"
    bat_file.write_text("@echo Test Batch File\nexit")
    files_created.append(("BAT File", str(bat_file), "CRITICAL"))
    
    # 3. JS file (suspicious)
    js_file = test_dir / "test.js"
    js_file.write_text("// Test JavaScript\nconsole.log('test');")
    files_created.append(("JS File", str(js_file), "MEDIUM"))
    
    # 4. VBS file (dangerous)
    vbs_file = test_dir / "test.vbs"
    vbs_file.write_text("' Test VBS\nMsgBox 'Test'")
    files_created.append(("VBS File", str(vbs_file), "CRITICAL"))
    
    # 5. Double extension file
    double_ext = test_dir / "document.pdf.exe"
    double_ext.write_text("Fake PDF")
    files_created.append(("Double Extension", str(double_ext), "CRITICAL"))
    
    # 6. Empty file
    empty_file = test_dir / "empty.dat"
    empty_file.write_bytes(b"")
    files_created.append(("Empty File", str(empty_file), "MEDIUM"))
    
    print(f"✅ Created {len(files_created)} test files in 'test_attachments/'\n")
    return files_created

def run_tests():
    """Run all attachment scanner tests"""
    print("="*70)
    print("         IR-DEPI Attachment Scanner Test Suite")
    print("="*70)
    print()
    
    scanner = AttachmentScanner()
    
    # Create test files
    test_files = create_test_files()
    
    results = []
    
    for name, file_path, expected in test_files:
        print(f"🔍 Testing: {name}")
        print(f"   File: {file_path}")
        
        result = scanner.scan_file(file_path)
        score = result['score']
        findings = len(result['findings'])
        
        # Determine verdict
        if score >= 50:
            verdict = "CRITICAL"
            color = "🔴"
        elif score >= 30:
            verdict = "HIGH"
            color = "🟠"
        elif score >= 15:
            verdict = "MEDIUM"
            color = "🟡"
        elif score > 0:
            verdict = "LOW"
            color = "🟢"
        else:
            verdict = "CLEAN"
            color = "✅"
        
        print(f"   Score: {score}")
        print(f"   Findings: {findings}")
        print(f"   Verdict: {color} {verdict}")
        
        # Show top findings
        if result['findings']:
            print(f"   Top Findings:")
            for f in result['findings'][:3]:
                print(f"      - [{f['severity']}] {f['description']}")
        
        print()
        
        results.append({
            'name': name,
            'score': score,
            'verdict': verdict,
            'findings': findings
        })
    
    # Summary
    print("="*70)
    print("                        TEST SUMMARY")
    print("="*70)
    print(f"{'Test Name':<25} | {'Score':<8} | {'Verdict':<15} | {'Findings':<10}")
    print("-"*70)
    
    for r in results:
        print(f"{r['name']:<25} | {r['score']:<8} | {r['verdict']:<15} | {r['findings']:<10}")
    
    print("="*70)
    
    # Cleanup option
    cleanup = input("\n🗑️  Delete test files? (y/n): ")
    if cleanup.lower() == 'y':
        import shutil
        test_dir = Path("test_attachments")
        if test_dir.exists():
            shutil.rmtree(test_dir)
            print("✅ Test files deleted.")
    
    print("\n✅ All tests completed!")

if __name__ == "__main__":
    run_tests()