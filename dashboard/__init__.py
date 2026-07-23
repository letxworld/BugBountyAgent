"""
BugBountyAgent - Dashboard Module
===================================
Web dashboard for controlling and monitoring the agent.
"""

from dashboard.app import create_app, run_dashboard, socketio
from dashboard.routes import register_routes
from dashboard.socket import register_socket_handlers

__all__ = [
    'create_app',
    'run_dashboard',
    'socketio',
    'register_routes',
    'register_socket_handlers'
]