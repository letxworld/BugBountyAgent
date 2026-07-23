"""
BugBountyAgent - Utilities
===========================
Utility functions for the agent.
"""

import os
import re
import json
import hashlib
import random
import string
from datetime import datetime
from typing import Dict, Any, Optional, List, Union
from urllib.parse import urlparse


def generate_id(length: int = 12) -> str:
    """Generate a random ID."""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))


def get_timestamp() -> str:
    """Get current timestamp."""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def get_date() -> str:
    """Get current date."""
    return datetime.now().strftime('%Y-%m-%d')


def hash_data(data: str, algorithm: str = 'sha256') -> str:
    """Hash data using specified algorithm."""
    if algorithm == 'sha256':
        return hashlib.sha256(data.encode()).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(data.encode()).hexdigest()
    else:
        return hashlib.sha256(data.encode()).hexdigest()


def safe_filename(filename: str) -> str:
    """Make a filename safe for file system."""
    safe = re.sub(r'[<>:"/\\|?*]', '_', filename)
    safe = re.sub(r'\s+', '_', safe)
    safe = safe.strip('._')
    if len(safe) > 255:
        name, ext = os.path.splitext(safe)
        safe = name[:250] + ext
    return safe


def truncate_text(text: str, max_length: int = 200, suffix: str = '...') -> str:
    """Truncate text to max length."""
    if not text or len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def is_url(text: str) -> bool:
    """Check if text is a valid URL."""
    try:
        result = urlparse(text)
        return all([result.scheme, result.netloc])
    except:
        return False


def is_ip(text: str) -> bool:
    """Check if text is a valid IP address."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, text):
        parts = text.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    if ':' in text:
        return len(text.split(':')) <= 8
    return False


def is_domain(text: str) -> bool:
    """Check if text is a valid domain."""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, text))


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        result = urlparse(url)
        domain = result.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return url


def parse_bool(value: Union[str, bool, int]) -> bool:
    """Parse a boolean from various formats."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in ['true', '1', 'yes', 'on', 'y', 't']
    return False


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Merge two dictionaries recursively."""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def print_banner() -> str:
    """Return the application banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   ██████╗ ██╗   ██╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗    ║
    ║   ██╔══██╗██║   ██║██╔════╝ ██╔══██╗██╔═══██╗╚██╗ ██╔╝    ║
    ║   ██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║ ╚████╔╝     ║
    ║   ██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║  ╚██╔╝      ║
    ║   ██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝   ██║       ║
    ║   ╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝       ║
    ║                                                              ║
    ║   BugBountyAgent - AI-Powered Bug Bounty Hunting            ║
    ║   v0.1.0                                                   ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    return banner