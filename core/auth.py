"""
BugBountyAgent - Authentication
=================================
Authentication handling for tokens, sessions, and credentials.
"""

import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from .config import Config
from .utils import get_timestamp


class AuthManager:
    """
    Authentication manager for tokens, sessions, and credentials.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.secret_key = config.get('auth.secret_key', 'dev-secret-key-change-me')
        self.token_expiry = config.get('auth.token_expiry', 3600)  # 1 hour
    
    # ============================================================
    # Token Management
    # ============================================================
    
    def generate_token(self, user_id: str, data: Optional[Dict] = None) -> str:
        """Generate a JWT token."""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(seconds=self.token_expiry),
            'iat': datetime.utcnow()
        }
        if data:
            payload.update(data)
        
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token."""
        try:
            return jwt.decode(token, self.secret_key, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def refresh_token(self, token: str) -> Optional[str]:
        """Refresh a token."""
        payload = self.verify_token(token)
        if not payload:
            return None
        
        # Remove old expiry and add new one
        payload.pop('exp', None)
        return self.generate_token(payload.get('user_id'), payload)
    
    # ============================================================
    # Password Management
    # ============================================================
    
    def hash_password(self, password: str) -> str:
        """Hash a password."""
        salt = secrets.token_hex(16)
        return salt + ':' + hashlib.sha256((salt + password).encode()).hexdigest()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify a password against a hash."""
        salt, hash_value = hashed.split(':')
        return hash_value == hashlib.sha256((salt + password).encode()).hexdigest()
    
    # ============================================================
    # API Key Management
    # ============================================================
    
    def generate_api_key(self) -> str:
        """Generate a new API key."""
        return secrets.token_urlsafe(32)
    
    def verify_api_key(self, api_key: str, valid_keys: List[str]) -> bool:
        """Verify an API key."""
        return api_key in valid_keys