"""
BugBountyAgent - Setting Model
================================
Database model for application settings and configurations.
"""

import uuid
import json
from datetime import datetime
from typing import Optional, Dict, Any, List, Union
from sqlalchemy import Column, String, DateTime, Integer, Text, Boolean, JSON, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Setting(Base):
    """Setting model representing application settings."""
    
    __tablename__ = 'settings'
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Setting details
    key = Column(String(100), nullable=False, unique=True)
    value = Column(Text, nullable=True)
    value_type = Column(String(20), default='string')  # string, integer, boolean, float, json, list
    
    # Metadata
    category = Column(String(50), nullable=True)  # general, agent, tools, dashboard, notifications
    description = Column(Text, nullable=True)
    is_encrypted = Column(Boolean, default=False)
    is_secret = Column(Boolean, default=False)
    is_readonly = Column(Boolean, default=False)
    
    # Validation
    validation_rules = Column(JSON, nullable=True, default=dict)  # min, max, regex, choices, etc.
    
    # Default value (for reference)
    default_value = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Setting(id={self.id}, key={self.key}, value_type={self.value_type})>"
    
    def get_value(self) -> Any:
        """Get the value with proper type conversion."""
        if self.value is None:
            return None
        
        try:
            if self.value_type == 'string':
                return str(self.value)
            elif self.value_type == 'integer':
                return int(self.value)
            elif self.value_type == 'boolean':
                return self.value.lower() in ['true', '1', 'yes', 'on']
            elif self.value_type == 'float':
                return float(self.value)
            elif self.value_type in ['json', 'list']:
                return json.loads(self.value)
            else:
                return self.value
        except (ValueError, json.JSONDecodeError):
            return self.value
    
    def set_value(self, value: Any) -> bool:
        """Set the value with proper type conversion."""
        try:
            if self.value_type == 'string':
                self.value = str(value)
            elif self.value_type == 'integer':
                self.value = str(int(value))
            elif self.value_type == 'boolean':
                self.value = 'true' if value else 'false'
            elif self.value_type == 'float':
                self.value = str(float(value))
            elif self.value_type == 'json':
                self.value = json.dumps(value)
            elif self.value_type == 'list':
                if isinstance(value, list):
                    self.value = json.dumps(value)
                else:
                    self.value = json.dumps(list(value))
            else:
                self.value = str(value)
            
            self.updated_at = datetime.utcnow()
            return True
        except (ValueError, TypeError, json.JSONEncodeError) as e:
            return False
    
    def validate(self, value: Any) -> bool:
        """Validate the value against validation rules."""
        if not self.validation_rules:
            return True
        
        rules = self.validation_rules
        
        # Check type
        if 'type' in rules:
            if rules['type'] == 'integer' and not isinstance(value, int):
                return False
            elif rules['type'] == 'boolean' and not isinstance(value, bool):
                return False
            elif rules['type'] == 'float' and not isinstance(value, float):
                return False
            elif rules['type'] == 'string' and not isinstance(value, str):
                return False
        
        # Check min/max
        if 'min' in rules and value < rules['min']:
            return False
        if 'max' in rules and value > rules['max']:
            return False
        
        # Check choices
        if 'choices' in rules and value not in rules['choices']:
            return False
        
        # Check regex (for strings)
        if 'regex' in rules and isinstance(value, str):
            import re
            if not re.match(rules['regex'], value):
                return False
        
        # Check min_length/max_length (for strings)
        if 'min_length' in rules and isinstance(value, str) and len(value) < rules['min_length']:
            return False
        if 'max_length' in rules and isinstance(value, str) and len(value) > rules['max_length']:
            return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'key': self.key,
            'value': self.get_value(),
            'value_type': self.value_type,
            'category': self.category,
            'description': self.description,
            'is_encrypted': self.is_encrypted,
            'is_secret': self.is_secret,
            'is_readonly': self.is_readonly,
            'validation_rules': self.validation_rules,
            'default_value': self.default_value,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def to_public_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with secrets hidden."""
        data = self.to_dict()
        if self.is_secret:
            data['value'] = '***HIDDEN***'
        return data
    
    @classmethod
    def get_default_settings(cls) -> Dict[str, Dict[str, Any]]:
        """Get default application settings."""
        return {
            # General settings
            'app_name': {
                'value': 'BugBountyAgent',
                'value_type': 'string',
                'category': 'general',
                'description': 'Application name',
                'is_secret': False,
                'is_readonly': True
            },
            'app_version': {
                'value': '0.1.0',
                'value_type': 'string',
                'category': 'general',
                'description': 'Application version',
                'is_secret': False,
                'is_readonly': True
            },
            'debug_mode': {
                'value': True,
                'value_type': 'boolean',
                'category': 'general',
                'description': 'Enable debug mode',
                'is_secret': False,
                'is_readonly': False,
                'validation_rules': {'type': 'boolean'}
            },
            'log_level': {
                'value': 'INFO',
                'value_type': 'string',
                'category': 'general',
                'description': 'Logging level',
                'is_secret': False,
                'is_readonly': False,
                'validation_rules': {
                    'choices': ['DEBUG', 'INFO', 'WARNING', 'ERROR']
                }
            },
            
            # Agent settings
            'agent_mode': {
                'value': 'hybrid',
                'value_type': 'string',
                'category': 'agent',
                'description': 'Agent operating mode',
                'is_secret': False,
                'is_readonly': False,
                'validation_rules': {
                    'choices': ['watch', 'full', 'hybrid', 'manual']
                }
            },
            'auto_approve': {
                'value': False,
                'value_type': 'boolean',
                'category': 'agent',
                'description': 'Auto-approve agent actions (DANGEROUS)',
                'is_secret': False,
                'is_readonly': False
            },
            'browser_control': {
                'value': True,
                'value_type': 'boolean',
                'category': 'agent',
                'description': 'Enable browser control',
                'is_secret': False,
                'is_readonly': False
            },
            
            # Tool settings
            'tools_auto_install': {
                'value': True,
                'value_type': 'boolean',
                'category': 'tools',
                'description': 'Auto-install missing tools',
                'is_secret': False,
                'is_readonly': False
            },
            'tools_update_on_start': {
                'value': False,
                'value_type': 'boolean',
                'category': 'tools',
                'description': 'Update tools on start',
                'is_secret': False,
                'is_readonly': False
            },
            
            # Dashboard settings
            'dashboard_host': {
                'value': '0.0.0.0',
                'value_type': 'string',
                'category': 'dashboard',
                'description': 'Dashboard host',
                'is_secret': False,
                'is_readonly': False
            },
            'dashboard_port': {
                'value': 5000,
                'value_type': 'integer',
                'category': 'dashboard',
                'description': 'Dashboard port',
                'is_secret': False,
                'is_readonly': False,
                'validation_rules': {'min': 1024, 'max': 65535}
            },
            'dashboard_secret_key': {
                'value': '',
                'value_type': 'string',
                'category': 'dashboard',
                'description': 'Dashboard secret key',
                'is_secret': True,
                'is_readonly': False
            },
            
            # Notification settings
            'notifications_enabled': {
                'value': True,
                'value_type': 'boolean',
                'category': 'notifications',
                'description': 'Enable notifications',
                'is_secret': False,
                'is_readonly': False
            },
            'telegram_bot_token': {
                'value': '',
                'value_type': 'string',
                'category': 'notifications',
                'description': 'Telegram bot token',
                'is_secret': True,
                'is_readonly': False
            },
            'telegram_chat_id': {
                'value': '',
                'value_type': 'string',
                'category': 'notifications',
                'description': 'Telegram chat ID',
                'is_secret': True,
                'is_readonly': False
            },
            
            # Security settings
            'max_scan_timeout': {
                'value': 3600,
                'value_type': 'integer',
                'category': 'security',
                'description': 'Maximum scan timeout in seconds',
                'is_secret': False,
                'is_readonly': False,
                'validation_rules': {'min': 60, 'max': 86400}
            },
            'max_concurrent_scans': {
                'value': 3,
                'value_type': 'integer',
                'category': 'security',
                'description': 'Maximum concurrent scans',
                'is_secret': False,
                'is_readonly': False,
                'validation_rules': {'min': 1, 'max': 10}
            },
            'rate_limit': {
                'value': 100,
                'value_type': 'integer',
                'category': 'security',
                'description': 'Rate limit per second',
                'is_secret': False,
                'is_readonly': False,
                'validation_rules': {'min': 1, 'max': 1000}
            },
            
            # Storage settings
            'max_storage_gb': {
                'value': 50,
                'value_type': 'integer',
                'category': 'storage',
                'description': 'Maximum storage in GB',
                'is_secret': False,
                'is_readonly': False,
                'validation_rules': {'min': 1, 'max': 500}
            },
            'auto_cleanup_days': {
                'value': 90,
                'value_type': 'integer',
                'category': 'storage',
                'description': 'Auto-cleanup days',
                'is_secret': False,
                'is_readonly': False,
                'validation_rules': {'min': 7, 'max': 365}
            },
            'compress_old_data': {
                'value': True,
                'value_type': 'boolean',
                'category': 'storage',
                'description': 'Compress data older than 30 days',
                'is_secret': False,
                'is_readonly': False
            }
        }
    
    @classmethod
    def create_defaults(cls):
        """Create default setting configuration."""
        return {
            'value_type': 'string',
            'is_encrypted': False,
            'is_secret': False,
            'is_readonly': False,
            'validation_rules': {}
        }