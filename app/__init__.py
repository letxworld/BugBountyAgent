"""
BugBountyAgent - Core Application Initialization
==================================================
This module initializes the entire application, including:
- Configuration loading
- Logging setup
- Database connections
- Tool management
- Agent initialization
- Dashboard setup
"""

import os
import sys
import yaml
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

# ============================================================
# Application Metadata
# ============================================================
__version__ = "0.1.0"
__app_name__ = "BugBountyAgent"
__description__ = "AI-powered bug bounty automation platform for ethical hackers"

# ============================================================
# Global Variables
# ============================================================
_config: Dict[str, Any] = {}
_logger: Optional[logging.Logger] = None
_db_session = None
_tool_manager = None
_agent = None

# ============================================================
# Configuration Loader
# ============================================================
def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to config file
        
    Returns:
        Dict: Configuration dictionary
    """
    global _config
    
    try:
        with open(config_path, 'r') as f:
            _config = yaml.safe_load(f)
        
        # Resolve environment variables in config
        _config = resolve_env_vars(_config)
        
        return _config
    except FileNotFoundError:
        print(f"[ERROR] Config file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"[ERROR] Failed to parse config: {e}")
        sys.exit(1)

def resolve_env_vars(obj: Any) -> Any:
    """
    Recursively resolve environment variables in config values.
    ${ENV_VAR} or $ENV_VAR will be replaced with actual value.
    """
    if isinstance(obj, dict):
        return {k: resolve_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [resolve_env_vars(item) for item in obj]
    elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
        # ${VAR_NAME} format
        var_name = obj[2:-1]
        return os.environ.get(var_name, obj)
    elif isinstance(obj, str) and obj.startswith("$"):
        # $VAR_NAME format
        var_name = obj[1:]
        return os.environ.get(var_name, obj)
    else:
        return obj

def get_config(key: str = None, default: Any = None) -> Any:
    """
    Get configuration value.
    
    Args:
        key: Dot notation key (e.g., "agent.model")
        default: Default value if key not found
        
    Returns:
        Any: Configuration value
    """
    global _config
    
    if not _config:
        load_config()
    
    if key is None:
        return _config
    
    # Navigate nested dictionaries using dot notation
    keys = key.split('.')
    value = _config
    for k in keys:
        if isinstance(value, dict) and k in value:
            value = value[k]
        else:
            return default
    return value

# ============================================================
# Logging Setup
# ============================================================
def setup_logging(log_level: str = "INFO", log_file: str = None) -> logging.Logger:
    """
    Setup application logging.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Path to log file (optional)
        
    Returns:
        logging.Logger: Configured logger
    """
    global _logger
    
    # Create logger
    logger = logging.getLogger(__app_name__)
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    _logger = logger
    return logger

def get_logger() -> logging.Logger:
    """Get the global logger instance."""
    global _logger
    if _logger is None:
        setup_logging()
    return _logger

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

# ============================================================
# Database Setup
# ============================================================
def setup_database(connection_string: str = None) -> Any:
    """
    Setup database connection.
    
    Args:
        connection_string: SQLAlchemy connection string
        
    Returns:
        Any: Database session/engine
    """
    global _db_session
    
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.ext.declarative import declarative_base
        
        if connection_string is None:
            # Use SQLite by default
            db_path = get_config('database.sqlite.path', './data/bugbounty.db')
            db_dir = os.path.dirname(db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            connection_string = f"sqlite:///{db_path}"
        
        engine = create_engine(connection_string, echo=False)
        Session = sessionmaker(bind=engine)
        _db_session = Session()
        
        return _db_session
    except ImportError:
        log_warning("SQLAlchemy not installed. Database features disabled.")
        return None
    except Exception as e:
        log_error(f"Failed to setup database: {e}")
        return None

def get_db_session():
    """Get the global database session."""
    global _db_session
    if _db_session is None:
        setup_database()
    return _db_session

# ============================================================
# Utility Functions
# ============================================================
def create_directories():
    """Create required directories from config."""
    dirs = [
        get_config('general.data_dir', './data'),
        get_config('general.logs_dir', './logs'),
        get_config('general.temp_dir', './temp'),
        get_config('reports.save_dir', './data/reports'),
        get_config('tools.install_dir', '/opt/bugbounty-tools'),
    ]
    
    for d in dirs:
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
            log_debug(f"Created directory: {d}")

def banner() -> str:
    """Return ASCII art banner."""
    return f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   ██████╗ ██╗   ██╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗    ║
    ║   ██╔══██╗██║   ██║██╔════╝ ██╔══██╗██╔═══██╗╚██╗ ██╔╝    ║
    ║   ██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║ ╚████╔╝     ║
    ║   ██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║  ╚██╔╝      ║
    ║   ██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝   ██║       ║
    ║   ╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝       ║
    ║                                                              ║
    ║   AI-Powered Bug Bounty Automation Platform                  ║
    ║   v{__version__}                                                   ║
    ║   {__description__}          ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """

def print_banner():
    """Print the application banner."""
    print(banner())

# ============================================================
# Main Initialization Function
# ============================================================
def init_app(config_path: str = "config/config.yaml", log_level: str = "INFO"):
    """
    Initialize the entire application.
    
    Args:
        config_path: Path to config file
        log_level: Logging level
    """
    # Load config
    load_config(config_path)
    
    # Setup logging
    log_file = get_config('general.logs_dir', './logs') + '/bugbounty.log'
    setup_logging(log_level, log_file)
    
    # Create directories
    create_directories()
    
    # Print banner
    print_banner()
    
    # Setup database
    setup_database()
    
    log_info(f"{__app_name__} v{__version__} initialized successfully")
    log_info(f"Config loaded from: {config_path}")
    log_info(f"Log level: {log_level}")
    log_info(f"Data directory: {get_config('general.data_dir')}")
    log_info(f"Log directory: {get_config('general.logs_dir')}")

# ============================================================
# Export
# ============================================================
__all__ = [
    '__version__',
    '__app_name__',
    '__description__',
    'load_config',
    'get_config',
    'setup_logging',
    'get_logger',
    'log_info',
    'log_warning',
    'log_error',
    'log_debug',
    'setup_database',
    'get_db_session',
    'init_app',
    'create_directories',
    'banner',
    'print_banner'
]

# ============================================================
# Auto-initialization (if run directly)
# ============================================================
if __name__ == "__main__":
    init_app()
    print("\n✅ BugBountyAgent initialized successfully!")
    print(f"   Dashboard: http://{get_config('dashboard.host', '127.0.0.1')}:{get_config('dashboard.port', 5000)}")