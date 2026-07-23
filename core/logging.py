"""
BugBountyAgent - Logging
=========================
Logging utilities for the application.
"""

import sys
import os
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional

# Global logger instance
_logger: Optional[logging.Logger] = None


def get_logger() -> logging.Logger:
    """Get the global logger instance."""
    global _logger
    if _logger is None:
        _logger = setup_logging()
    return _logger


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Setup application logging."""
    logger = logging.getLogger('BugBountyAgent')
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(file_handler)
    
    return logger


def log_info(msg: str):
    """Log info message."""
    get_logger().info(msg)


def log_warning(msg: str):
    """Log warning message."""
    get_logger().warning(msg)


def log_error(msg: str):
    """Log error message."""
    get_logger().error(msg)


def log_debug(msg: str):
    """Log debug message."""
    get_logger().debug(msg)


def log_critical(msg: str):
    """Log critical message."""
    get_logger().critical(msg)