"""
IR-DEPI | User Authentication Module
JWT-based authentication with role-based access control
"""

import jwt
import bcrypt
import os
import re
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

# JWT Configuration
JWT_SECRET = os.getenv('JWT_SECRET', 'change-this-in-production-please!')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# User roles
ROLE_ADMIN = 'admin'
ROLE_ANALYST = 'analyst'
ROLE_VIEWER = 'viewer'


class User:
    """User model for authentication"""
    
    def __init__(self, user_id, username, email, role, created_at=None):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.role = role
        self.created_at = created_at or datetime.now().isoformat()
        self.password_hash = None
    
    def to_dict(self):
        return {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at
        }


class AuthManager:
    """Manages user authentication and authorization"""
    
    def __init__(self, db_connection=None):
        self.db = db_connection
        self._init_jwt_secret()
    
    def _init_jwt_secret(self):
        """Generate JWT secret if not exists"""
        global JWT_SECRET
        if JWT_SECRET == 'change-this-in-production-please!':
            JWT_SECRET = os.urandom(32).hex()
            # Save to .env (optional)
            print(f"⚠️  Generated new JWT_SECRET: {JWT_SECRET[:20]}...")
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def validate_username(self, username: str) -> tuple[bool, str]:
        """Validate username format"""
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        if len(username) > 50:
            return False, "Username must be less than 50 characters"
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, _ and -"
        return True, ""
    
    def validate_email(self, email: str) -> tuple[bool, str]:
        """Validate email format"""
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return False, "Invalid email format"
        return True, ""
    
    def validate_password(self, password: str) -> tuple[bool, str]:
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        return True, ""
    
    def generate_token(self, user: User) -> str:
        """Generate JWT token for user"""
        payload = {
            'user_id': user.user_id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    def decode_token(self, token: str) -> dict | None:
        """Decode and validate JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def require_auth(self, func):
        """Decorator to require authentication for a function"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get token from kwargs or args
            token = kwargs.get('token') or (args[1] if len(args) > 1 else None)
            
            if not token:
                return {'error': 'Authentication required', 'status': 401}
            
            payload = self.decode_token(token)
            if not payload:
                return {'error': 'Invalid or expired token', 'status': 401}
            
            # Add user info to kwargs
            kwargs['current_user'] = payload
            return func(*args, **kwargs)
        return wrapper
    
    def require_role(self, *allowed_roles):
        """Decorator to require specific role(s)"""
        def decorator(func):
            @wraps(func)
            @self.require_auth
            def wrapper(*args, **kwargs):
                current_user = kwargs.get('current_user')
                if current_user.get('role') not in allowed_roles:
                    return {'error': 'Insufficient permissions', 'status': 403}
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def register_user(self, username: str, email: str, password: str, role: str = ROLE_VIEWER) -> dict:
        """Register a new user"""
        # Validate inputs
        valid, msg = self.validate_username(username)
        if not valid:
            return {'success': False, 'error': msg}
        
        valid, msg = self.validate_email(email)
        if not valid:
            return {'success': False, 'error': msg}
        
        valid, msg = self.validate_password(password)
        if not valid:
            return {'success': False, 'error': msg}
        
        if role not in [ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER]:
            return {'success': False, 'error': 'Invalid role'}
        
        # Hash password
        password_hash = self.hash_password(password)
        
        # Create user (in real app, save to database)
        user = User(
            user_id=f"user_{datetime.now().timestamp()}",
            username=username,
            email=email,
            role=role
        )
        user.password_hash = password_hash
        
        return {
            'success': True,
            'message': 'User registered successfully',
            'user': user.to_dict(),
            'token': self.generate_token(user)
        }
    
    def login(self, username_or_email: str, password: str) -> dict:
        """Authenticate user and return token"""
        # In real app, fetch user from database
        # For demo, we'll use a simple check
        
        # Demo admin credentials (CHANGE IN PRODUCTION!)
        demo_users = {
            'admin': {
                'password_hash': self.hash_password('Admin@123'),
                'user': User('admin_001', 'admin', 'admin@ir-depi.local', ROLE_ADMIN)
            },
            'analyst': {
                'password_hash': self.hash_password('Analyst@123'),
                'user': User('analyst_001', 'analyst', 'analyst@ir-depi.local', ROLE_ANALYST)
            }
        }
        
        # Find user
        user_data = None
        for key, data in demo_users.items():
            if key == username_or_email or data['user'].email == username_or_email:
                user_data = data
                break
        
        if not user_data:
            return {'success': False, 'error': 'Invalid credentials'}
        
        # Verify password
        if not self.verify_password(password, user_data['password_hash']):
            return {'success': False, 'error': 'Invalid credentials'}
        
        user = user_data['user']
        
        return {
            'success': True,
            'message': 'Login successful',
            'user': user.to_dict(),
            'token': self.generate_token(user)
        }
    
    def refresh_token(self, token: str) -> dict:
        """Refresh an expiring token"""
        payload = self.decode_token(token)
        if not payload:
            return {'success': False, 'error': 'Invalid token'}
        
        # Create new token with same user data
        new_token = jwt.encode({
            'user_id': payload['user_id'],
            'username': payload['username'],
            'email': payload['email'],
            'role': payload['role'],
            'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
            'iat': datetime.utcnow()
        }, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        return {
            'success': True,
            'token': new_token,
            'expires_in': JWT_EXPIRATION_HOURS * 3600
        }


# Global auth manager instance
auth_manager = AuthManager()


# Convenience functions
def generate_token(user: User) -> str:
    return auth_manager.generate_token(user)

def decode_token(token: str) -> dict | None:
    return auth_manager.decode_token(token)

def require_auth(func):
    return auth_manager.require_auth(func)

def require_role(*roles):
    return auth_manager.require_role(*roles)