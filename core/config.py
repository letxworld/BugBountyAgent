"""
BugBountyAgent - Configuration Loader
=======================================
Loads and manages configuration from YAML files.
Supports environment variable substitution.
"""

import os
import sys
import yaml
from typing import Dict, Any, Optional
from pathlib import Path


class Config:
    """
    Configuration manager with environment variable support.
    """
    
    DEFAULT_CONFIG = {
        'agent': {
            'mode': 'hybrid',
            'auto_approve': False,
            'require_confirmation': True
        },
        'browser': {
            'headless': False,
            'proxy': None
        },
        'system': {
            'data_dir': './data',
            'logs_dir': './logs',
            'reports_dir': './data/reports',
            'findings_dir': './data/findings',
            'chains_dir': './data/chains',
            'patterns_dir': './data/patterns',
            'screenshots_dir': './data/screenshots',
            'tool_outputs_dir': './data/tool_outputs',
            'temp_dir': './data/temp',
            'command_whitelist': [],
            'command_blacklist': ['rm -rf /', 'dd', 'mkfs', 'shutdown', 'reboot'],
            'command_timeout': 300,
            'working_dir': '.'
        },
        'scanner': {
            'timeout': 300,
            'severity_filter': ['low', 'medium', 'high', 'critical']
        },
        'learning': {
            'enabled': True,
            'confidence_threshold': 0.7,
            'knowledge_path': './data/knowledge/knowledge.json'
        },
        'dashboard': {
            'enabled': True,
            'host': '0.0.0.0',
            'port': 5000,
            'debug': True
        },
        'storage': {
            'max_total_gb': 50,
            'auto_cleanup': True,
            'retention': {
                'logs': 30,
                'reports': 60,
                'screenshots': 30,
                'findings': 365,
                'chains': 180,
                'patterns': 180,
                'tool_outputs': 30
            }
        },
        'database': {
            'path': './data/state.db'
        }
    }
    
    def __init__(self, config_path: str = 'config.yaml'):
        """
        Initialize configuration.
        
        Args:
            config_path: Path to config file
        """
        self.config_path = config_path
        self._config = self.DEFAULT_CONFIG.copy()
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file."""
        if not os.path.exists(self.config_path):
            # Create default config file
            self._save_config()
            return
        
        try:
            with open(self.config_path, 'r') as f:
                loaded = yaml.safe_load(f)
                if loaded:
                    self._deep_merge(self._config, loaded)
        except Exception as e:
            print(f"⚠️ Failed to load config: {e}")
    
    def _save_config(self):
        """Save current configuration to file."""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                yaml.dump(self._config, f, default_flow_style=False)
        except Exception as e:
            print(f"⚠️ Failed to save config: {e}")
    
    def _deep_merge(self, base: Dict, override: Dict):
        """Deep merge two dictionaries."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            key: Dot notation key (e.g., 'agent.mode')
            default: Default value if key not found
            
        Returns:
            Any: Configuration value
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """
        Set a configuration value using dot notation.
        
        Args:
            key: Dot notation key (e.g., 'agent.mode')
            value: Value to set
        """
        keys = key.split('.')
        target = self._config
        
        for k in keys[:-1]:
            if k not in target or not isinstance(target[k], dict):
                target[k] = {}
            target = target[k]
        
        target[keys[-1]] = value
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration."""
        return self._config.copy()
    
    def reload(self):
        """Reload configuration from file."""
        self._load_config()
    
    def save(self):
        """Save configuration to file."""
        self._save_config()
    
    def get_env_var(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get an environment variable."""
        return os.environ.get(key, default)
    
    def resolve_env_vars(self, value: Any) -> Any:
        """
        Resolve environment variables in a value.
        Replaces ${VAR_NAME} with the environment variable value.
        """
        if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
            var_name = value[2:-1]
            return self.get_env_var(var_name, value)
        elif isinstance(value, dict):
            return {k: self.resolve_env_vars(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self.resolve_env_vars(item) for item in value]
        else:
            return value
    
    def get_resolved(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value with environment variable resolution.
        
        Args:
            key: Dot notation key
            default: Default value
            
        Returns:
            Any: Resolved value
        """
        value = self.get(key, default)
        return self.resolve_env_vars(value)


# ============================================================
# Global Config Instance
# ============================================================

_config_instance: Optional[Config] = None


def get_config(config_path: str = 'config.yaml') -> Config:
    """
    Get the global configuration instance.
    
    Args:
        config_path: Path to config file
        
    Returns:
        Config: Configuration instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(config_path)
    return _config_instance


def reset_config():
    """Reset the global configuration instance."""
    global _config_instance
    _config_instance = None