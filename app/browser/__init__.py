"""
BugBountyAgent - Browser Automation Module
===========================================
This module provides browser automation capabilities for the agent:
- Opening and controlling browsers
- Navigating websites
- Clicking, typing, and interacting with pages
- Intercepting and modifying requests
- Taking screenshots
- Learning from user behavior
"""

from app.browser.controller import BrowserController
from app.browser.proxy import ProxyInterceptor
from app.browser.recorder import BehaviorRecorder
from app.browser.actions import BrowserActions

__all__ = [
    'BrowserController',
    'ProxyInterceptor',
    'BehaviorRecorder',
    'BrowserActions'
]