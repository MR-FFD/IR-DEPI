"""SQLite Database Module for IR-DEPI - Updated with User Authentication"""

import sqlite3
from datetime import datetime
import json
import os
from typing import List, Dict, Any, Optional

# Import auth for user management
from auth import auth_manager, User, ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER


class PhishingDatabase:
    """Database management for analysis history and users"""
    
    def __init__(self, db_path: str = "data/phishing_analysis.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.init_database()
        self._create_default_users()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Analysis history table (existing)
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
        
        # Users table (NEW)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TEXT NOT NULL,
                last_login TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        # Audit log table (NEW)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                details TEXT,
                ip_address TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _create_default_users(self):
        """Create default admin and analyst users if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        default_users = [
            ('admin_001', 'admin', 'admin@ir-depi.local', ROLE_ADMIN, 'Admin@123'),
            ('analyst_001', 'analyst', 'analyst@ir-depi.local', ROLE_ANALYST, 'Analyst@123'),
        ]
        
        for user_id, username, email, role, password in default_users:
            # Check if user exists
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if not cursor.fetchone():
                password_hash = auth_manager.hash_password(password)
                cursor.execute('''
                    INSERT INTO users (user_id, username, email, password_hash, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, username, email, password_hash, role, datetime.now().isoformat()))
                print(f"✅ Created default user: {username} ({role})")
        
        conn.commit()
        conn.close()
    
    # ============ User Management Methods ============
    
    def create_user(self, username: str, email: str, password: str, role: str = ROLE_VIEWER, created_by: str = None) -> dict:
        """Create a new user"""
        # Validate first
        result = auth_manager.register_user(username, email, password, role)
        if not result['success']:
            return result
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (user_id, username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                result['user']['user_id'],
                username,
                email,
                auth_manager.hash_password(password),
                role,
                datetime.now().isoformat()
            ))
            
            # Log the action
            self._log_audit(created_by, 'user_created', 'users', f'Created user: {username}')
            
            conn.commit()
            return {'success': True, 'message': 'User created successfully', 'user': result['user']}
            
        except sqlite3.IntegrityError as e:
            return {'success': False, 'error': 'Username or email already exists'}
        finally:
            conn.close()
    
    def authenticate_user(self, username_or_email: str, password: str) -> dict:
        """Authenticate user against database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM users 
            WHERE (username = ? OR email = ?) AND is_active = 1
        ''', (username_or_email, username_or_email))
        
        user_row = cursor.fetchone()
        conn.close()
        
        if not user_row:
            return {'success': False, 'error': 'Invalid credentials'}
        
        # Verify password
        if not auth_manager.verify_password(password, user_row['password_hash']):
            return {'success': False, 'error': 'Invalid credentials'}
        
        # Update last login
        self._update_last_login(user_row['user_id'])
        
        # Create user object
        user = User(
            user_id=user_row['user_id'],
            username=user_row['username'],
            email=user_row['email'],
            role=user_row['role'],
            created_at=user_row['created_at']
        )
        
        # Log the login
        self._log_audit(user_row['user_id'], 'login', 'auth', 'User logged in')
        
        return {
            'success': True,
            'message': 'Login successful',
            'user': user.to_dict(),
            'token': auth_manager.generate_token(user)
        }
    
    def _update_last_login(self, user_id: str):
        """Update user's last login timestamp"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET last_login = ? WHERE user_id = ?
        ''', (datetime.now().isoformat(), user_id))
        conn.commit()
        conn.close()
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        """Get user details by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        user_row = cursor.fetchone()
        conn.close()
        
        if user_row:
            return dict(user_row)
        return None
    
    def list_users(self, limit: int = 100) -> List[Dict]:
        """List all users (admin only)"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, user_id, username, email, role, created_at, last_login, is_active
            FROM users ORDER BY created_at DESC LIMIT ?
        ''', (limit,))
        
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return users
    
    def update_user_role(self, user_id: str, new_role: str, updated_by: str = None) -> dict:
        """Update user role (admin only)"""
        if new_role not in [ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER]:
            return {'success': False, 'error': 'Invalid role'}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET role = ? WHERE user_id = ?
        ''', (new_role, user_id))
        
        if cursor.rowcount > 0:
            self._log_audit(updated_by, 'role_updated', 'users', f'Updated {user_id} role to {new_role}')
            conn.commit()
            conn.close()
            return {'success': True, 'message': 'Role updated successfully'}
        
        conn.close()
        return {'success': False, 'error': 'User not found'}
    
    def deactivate_user(self, user_id: str, deactivated_by: str = None) -> dict:
        """Deactivate a user account"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET is_active = 0 WHERE user_id = ?
        ''', (user_id,))
        
        if cursor.rowcount > 0:
            self._log_audit(deactivated_by, 'user_deactivated', 'users', f'Deactivated user: {user_id}')
            conn.commit()
            conn.close()
            return {'success': True, 'message': 'User deactivated'}
        
        conn.close()
        return {'success': False, 'error': 'User not found'}
    
    # ============ Audit Logging ============
    
    def _log_audit(self, user_id: Optional[str], action: str, resource: str, details: str, ip_address: str = None):
        """Log an audit event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO audit_log (timestamp, user_id, action, resource, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            user_id,
            action,
            resource,
            details,
            ip_address
        ))
        
        conn.commit()
        conn.close()
    
    def get_audit_log(self, user_id: str = None, limit: int = 100) -> List[Dict]:
        """Get audit log entries"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute('''
                SELECT * FROM audit_log 
                WHERE user_id = ? 
                ORDER BY timestamp DESC LIMIT ?
            ''', (user_id, limit))
        else:
            cursor.execute('''
                SELECT * FROM audit_log 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
        
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return logs
    
    # ============ Existing Analysis Methods (unchanged) ============
    
    def save_analysis(self, result: Dict[str, Any], file_path: str, duration: float = 0.0, user_id: str = None):
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
        
        # Log the analysis
        if user_id:
            self._log_audit(user_id, 'analysis_run', 'email', f'Analyzed: {file_path}')
        
        conn.commit()
        conn.close()
    
    def get_all_analyses(self, limit: int = 100, user_id: str = None) -> List[Dict]:
        """Get all analysis records"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM analysis_history ORDER BY timestamp DESC LIMIT ?', (limit,))
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM analysis_history')
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM analysis_history WHERE verdict = 'PHISHING_DETECTED'")
        phishing = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM analysis_history WHERE verdict = 'SUSPICIOUS'")
        suspicious = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM analysis_history WHERE verdict = 'CLEAN'")
        clean = cursor.fetchone()[0]
        
        cursor.execute('SELECT AVG(risk_score) FROM analysis_history')
        avg_score = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'total_analyses': total,
            'phishing_detected': phishing,
            'suspicious': suspicious,
            'clean': clean,
            'average_score': round(avg_score, 2)
        }
    
    def search_analyses(self, keyword: str) -> List[Dict]:
        """Search analyses by keyword"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM analysis_history 
            WHERE email_from LIKE ? OR email_subject LIKE ? OR verdict LIKE ?
            ORDER BY timestamp DESC LIMIT 50
        ''', (f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results