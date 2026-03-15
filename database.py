"""
Enterprise Database Module for IR-DEPI
SQLite-based storage for phishing analysis history
"""

import sqlite3
from datetime import datetime
import json
import os
from typing import List, Dict, Any, Optional

class PhishingDatabase:
    def __init__(self, db_path: str = "data/phishing_analysis.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Analysis History Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                email_from TEXT,
                email_to TEXT,
                email_subject TEXT,
                file_path TEXT,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                findings_count INTEGER,
                findings_json TEXT,
                analysis_duration REAL
            )
        ''')
        
        # Statistics View
        cursor.execute('''
            CREATE VIEW IF NOT EXISTS daily_stats AS
            SELECT 
                DATE(timestamp) as analysis_date,
                COUNT(*) as total_analyses,
                SUM(CASE WHEN verdict = 'PHISHING_DETECTED' THEN 1 ELSE 0 END) as phishing_count,
                SUM(CASE WHEN verdict = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious_count,
                SUM(CASE WHEN verdict = 'CLEAN' THEN 1 ELSE 0 END) as clean_count,
                AVG(risk_score) as avg_score
            FROM analysis_history
            GROUP BY DATE(timestamp)
        ''')
        
        conn.commit()
        conn.close()
    
    def save_analysis(self, result: Dict[str, Any], file_path: str, duration: float = 0.0):
        """Save analysis result to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        metadata = result.get('metadata', {})
        
        cursor.execute('''
            INSERT INTO analysis_history 
            (timestamp, email_from, email_to, email_subject, file_path, 
             verdict, risk_score, findings_count, findings_json, analysis_duration)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            metadata.get('from', 'N/A'),
            metadata.get('to', 'N/A'),
            metadata.get('subject', 'N/A'),
            file_path,
            result.get('verdict', 'UNKNOWN'),
            result.get('score', 0),
            len(result.get('findings', [])),
            json.dumps(result.get('findings', [])),
            duration
        ))
        
        conn.commit()
        conn.close()
    
    def get_all_analyses(self, limit: int = 100) -> List[Dict]:
        """Get all analysis records"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM analysis_history 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total analyses
        cursor.execute('SELECT COUNT(*) FROM analysis_history')
        total = cursor.fetchone()[0]
        
        # Phishing count
        cursor.execute("SELECT COUNT(*) FROM analysis_history WHERE verdict = 'PHISHING_DETECTED'")
        phishing = cursor.fetchone()[0]
        
        # Suspicious count
        cursor.execute("SELECT COUNT(*) FROM analysis_history WHERE verdict = 'SUSPICIOUS'")
        suspicious = cursor.fetchone()[0]
        
        # Clean count
        cursor.execute("SELECT COUNT(*) FROM analysis_history WHERE verdict = 'CLEAN'")
        clean = cursor.fetchone()[0]
        
        # Average score
        cursor.execute('SELECT AVG(risk_score) FROM analysis_history')
        avg_score = cursor.fetchone()[0] or 0
        
        # Recent analyses (last 7 days)
        cursor.execute('''
            SELECT COUNT(*) FROM analysis_history 
            WHERE timestamp >= datetime('now', '-7 days')
        ''')
        recent = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_analyses': total,
            'phishing_detected': phishing,
            'suspicious': suspicious,
            'clean': clean,
            'average_score': round(avg_score, 2),
            'last_7_days': recent
        }
    
    def search_analyses(self, keyword: str) -> List[Dict]:
        """Search analyses by keyword"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM analysis_history 
            WHERE email_from LIKE ? OR email_subject LIKE ? OR verdict LIKE ?
            ORDER BY timestamp DESC
            LIMIT 50
        ''', (f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def get_daily_stats(self, days: int = 30) -> List[Dict]:
        """Get daily statistics for the last N days"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM daily_stats 
            ORDER BY analysis_date DESC 
            LIMIT ?
        ''', (days,))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def clear_history(self):
        """Clear all analysis history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM analysis_history')
        conn.commit()
        conn.close()


# Test function
if __name__ == "__main__":
    db = PhishingDatabase()
    print("Database initialized successfully!")
    
    # Test save
    test_result = {
        "verdict": "PHISHING_DETECTED",
        "score": 75,
        "metadata": {
            "from": "test@example.com",
            "to": "user@company.com",
            "subject": "Test Email"
        },
        "findings": [
            {"severity": "HIGH", "category": "Link", "description": "Suspicious link"}
        ]
    }
    
    db.save_analysis(test_result, "test.eml", 0.5)
    print("Test analysis saved!")
    
    # Test statistics
    stats = db.get_statistics()
    print(f"Statistics: {stats}")