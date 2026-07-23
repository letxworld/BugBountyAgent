"""
BugBountyAgent - Custom Exceptions
====================================
Custom exceptions for the application.
"""


class BugBountyAgentError(Exception):
    """Base exception for BugBountyAgent."""
    pass


class ConfigurationError(BugBountyAgentError):
    """Configuration related errors."""
    pass


class TargetError(BugBountyAgentError):
    """Target related errors."""
    pass


class ScanError(BugBountyAgentError):
    """Scan related errors."""
    pass


class ToolError(BugBountyAgentError):
    """Tool related errors."""
    pass


class BrowserError(BugBountyAgentError):
    """Browser automation errors."""
    pass


class SystemAccessError(BugBountyAgentError):
    """System access errors."""
    pass


class LearningError(BugBountyAgentError):
    """Learning engine errors."""
    pass


class ReportError(BugBountyAgentError):
    """Report generation errors."""
    pass


class DatabaseError(BugBountyAgentError):
    """Database errors."""
    pass


class AuthError(BugBountyAgentError):
    """Authentication errors."""
    pass


class TimeoutError(BugBountyAgentError):
    """Timeout errors."""
    pass


class PermissionError(BugBountyAgentError):
    """Permission errors."""
    pass


class NotFoundError(BugBountyAgentError):
    """Not found errors."""
    pass