"""
BugBountyAgent - Core Initialization
=====================================
This module loads configuration, sets up logging,
initializes the database, and provides core utilities.
"""

import os
import sys
import yaml
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import json
import hashlib

# ============================================================
# Application Metadata
# ============================================================
__version__ = "0.1.0"
__app_name__ = "BugBountyAgent"
__description__ = "AI-powered autonomous bug bounty hunting platform"

# ============================================================
# Global State
# ============================================================
_config: Dict[str, Any] = {}
_logger: Optional[logging.Logger] = None
_db_session = None
_knowledge_base = None
_chain_manager = None
_agent_instance = None

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
    """Recursively resolve environment variables in config."""
    if isinstance(obj, dict):
        return {k: resolve_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [resolve_env_vars(item) for item in obj]
    elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
        var_name = obj[2:-1]
        return os.environ.get(var_name, obj)
    elif isinstance(obj, str) and obj.startswith("$"):
        var_name = obj[1:]
        return os.environ.get(var_name, obj)
    else:
        return obj

def get_config(key: str = None, default: Any = None) -> Any:
    """
    Get configuration value using dot notation.
    
    Examples:
        get_config('agent.mode') -> 'hybrid'
        get_config('dashboard.port') -> 5000
    """
    global _config
    
    if not _config:
        load_config()
    
    if key is None:
        return _config
    
    keys = key.split('.')
    value = _config
    for k in keys:
        if isinstance(value, dict) and k in value:
            value = value[k]
        else:
            return default
    return value

def save_config(config_path: str = "config/config.yaml") -> bool:
    """Save current configuration to file."""
    global _config
    
    try:
        with open(config_path, 'w') as f:
            yaml.dump(_config, f, default_flow_style=False)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save config: {e}")
        return False

# ============================================================
# Logging Setup
# ============================================================
def setup_logging(log_level: str = "INFO", log_file: str = None) -> logging.Logger:
    """Setup application logging."""
    global _logger
    
    logger = logging.getLogger(__app_name__)
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        max_bytes = get_config('system.max_file_size', 10485760)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
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
    get_logger().info(msg)

def log_warning(msg: str):
    get_logger().warning(msg)

def log_error(msg: str):
    get_logger().error(msg)

def log_debug(msg: str):
    get_logger().debug(msg)

def log_critical(msg: str):
    get_logger().critical(msg)

# ============================================================
# Database Setup
# ============================================================
def setup_database(connection_string: str = None):
    """Setup database connection."""
    global _db_session
    
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.ext.declarative import declarative_base
        
        if connection_string is None:
            db_type = get_config('database.type', 'sqlite')
            if db_type == 'sqlite':
                db_path = get_config('database.sqlite.path', './data/bugbounty.db')
                db_dir = os.path.dirname(db_path)
                if db_dir and not os.path.exists(db_dir):
                    os.makedirs(db_dir, exist_ok=True)
                connection_string = f"sqlite:///{db_path}"
            elif db_type == 'postgresql':
                host = get_config('database.postgresql.host', 'localhost')
                port = get_config('database.postgresql.port', 5432)
                db = get_config('database.postgresql.database', 'bugbounty')
                user = get_config('database.postgresql.username', 'bugbounty')
                password = get_config('database.postgresql.password', '')
                connection_string = f"postgresql://{user}:{password}@{host}:{port}/{db}"
        
        engine = create_engine(connection_string, echo=False)
        Session = sessionmaker(bind=engine)
        _db_session = Session()
        
        # Create Base for models
        Base = declarative_base()
        Base.metadata.create_all(engine)
        
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
# Knowledge Base
# ============================================================
def init_knowledge_base():
    """Initialize the knowledge base."""
    global _knowledge_base
    
    try:
        from app.knowledge.knowledge_base import KnowledgeBase
        _knowledge_base = KnowledgeBase()
        return _knowledge_base
    except ImportError:
        log_warning("Knowledge base not available.")
        return None

def get_knowledge_base():
    """Get the knowledge base instance."""
    global _knowledge_base
    if _knowledge_base is None:
        init_knowledge_base()
    return _knowledge_base

# ============================================================
# Chain Manager
# ============================================================
def init_chain_manager():
    """Initialize the chain manager."""
    global _chain_manager
    
    try:
        from app.learners.chain_manager import ChainManager
        _chain_manager = ChainManager()
        return _chain_manager
    except ImportError:
        log_warning("Chain manager not available.")
        return None

def get_chain_manager():
    """Get the chain manager instance."""
    global _chain_manager
    if _chain_manager is None:
        init_chain_manager()
    return _chain_manager

# ============================================================
# Utility Functions
# ============================================================
def create_directories():
    """Create all required directories."""
    dirs = [
        get_config('general.data_dir', './data'),
        get_config('general.logs_dir', './logs'),
        get_config('general.temp_dir', './temp'),
        get_config('reports.save_dir', './data/reports'),
        get_config('chain_hunting.chains_dir', './data/chains'),
        get_config('chain_hunting.patterns_dir', './data/patterns'),
        get_config('chain_hunting.findings_dir', './data/findings'),
        get_config('learning.patterns_dir', './data/patterns'),
        get_config('tools.install_dir', '/opt/bugbounty-tools'),
        get_config('database.sqlite.path', './data').split('/')[0],
    ]
    
    for d in dirs:
        if d and not os.path.exists(d):
            try:
                os.makedirs(d, exist_ok=True)
                log_debug(f"Created directory: {d}")
            except PermissionError:
                log_warning(f"Cannot create directory (permission denied): {d}")
            except Exception as e:
                log_warning(f"Failed to create directory {d}: {e}")

def generate_id(length: int = 12) -> str:
    """Generate a random ID."""
    import random
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def hash_data(data: str) -> str:
    """Hash data using SHA-256."""
    return hashlib.sha256(data.encode()).hexdigest()

def safe_filename(filename: str) -> str:
    """Make a filename safe for file system."""
    import re
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)

def get_timestamp() -> str:
    """Get current timestamp as string."""
    return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

def get_date() -> str:
    """Get current date as string."""
    return datetime.now().strftime('%Y-%m-%d')

# ============================================================
# Banner
# ============================================================
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
    ║   Autonomous Bug Bounty Hunting Platform                    ║
    ║   v{__version__}                                                   ║
    ║   {__description__}          ║
    ║                                                              ║
    ║   📡 Mode: {get_config('agent.mode', 'hybrid').upper()}                    ║
    ║   🎯 Targets: {len(get_config('targets.scope', []))}                        ║
    ║   🧠 Learning: {'ON' if get_config('learning.enabled', True) else 'OFF'}    ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """

def print_banner():
    """Print the application banner."""
    print(banner())

# ============================================================
# Main Initialization
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
    log_file = f"{get_config('general.logs_dir', './logs')}/bugbounty.log"
    setup_logging(log_level, log_file)
    
    # Create directories
    create_directories()
    
    # Print banner
    print_banner()
    
    # Setup database
    setup_database()
    
    # Initialize knowledge base
    init_knowledge_base()
    
    # Initialize chain manager
    init_chain_manager()
    
    log_info(f"{__app_name__} v{__version__} initialized successfully")
    log_info(f"Config loaded from: {config_path}")
    log_info(f"Log level: {log_level}")
    log_info(f"Mode: {get_config('agent.mode', 'hybrid')}")
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
    'save_config',
    'setup_logging',
    'get_logger',
    'log_info',
    'log_warning',
    'log_error',
    'log_debug',
    'log_critical',
    'setup_database',
    'get_db_session',
    'init_knowledge_base',
    'get_knowledge_base',
    'init_chain_manager',
    'get_chain_manager',
    'init_app',
    'create_directories',
    'generate_id',
    'hash_data',
    'safe_filename',
    'get_timestamp',
    'get_date',
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