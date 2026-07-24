"""
BugBountyAgent - Dashboard Module
===================================
Web dashboard for controlling and monitoring the agent.
"""

from dashboard.app import create_app, run_dashboard, socketio, app, get_agent, get_tools
from dashboard.routes import register_routes

__all__ = [
    'create_app',
    'run_dashboard',
    'socketio',
    'app',
    'get_agent',
    'get_tools',
    'register_routes'
]
