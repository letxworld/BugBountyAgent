"""
BugBountyAgent - Database Models
=================================
This module defines all database models for the application:
- Target: Targets being scanned
- Finding: Discovered vulnerabilities
- Scan: Scan sessions and results
- Chain: Attack chains
- Profile: Target profiles with aggregated data
- Setting: Application settings
"""

from app.models.target import Target
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.chain import Chain
from app.models.profile import Profile
from app.models.setting import Setting

__all__ = [
    'Target',
    'Finding',
    'Scan',
    'Chain',
    'Profile',
    'Setting'
]