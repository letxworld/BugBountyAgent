"""
BugBountyAgent - Dashboard Module
==================================
This module provides the web-based dashboard for controlling and monitoring
the bug hunting agent. It includes:
- Flask web application
- REST API endpoints
- WebSocket real-time updates
- Interactive UI
- System monitoring
"""

from app.dashboard.app import create_app
from app.dashboard.routes import register_routes
from app.dashboard.socket_handler import register_socket_handlers

__all__ = [
    'create_app',
    'register_routes',
    'register_socket_handlers'
]