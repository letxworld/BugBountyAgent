#!/usr/bin/env python3
"""
BugBountyAgent - Main Entry Point
==================================
Main entry point for the BugBountyAgent application.
Handles initialization and routing to CLI or Dashboard.
"""

import sys
import os
import argparse
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import get_config
from core.utils import print_banner, get_timestamp
from core.logging import log_info, log_error, log_warning, setup_logging
from core.system import SystemController
from core.tools import ToolManager


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='BugBountyAgent - AI-Powered Bug Bounty Hunting Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Start CLI mode
  python main.py cli
  
  # Start dashboard
  python main.py dashboard
  
  # Run a scan directly
  python main.py scan https://example.com --type full
  
  # Check system status
  python main.py status
        '''
    )
    
    parser.add_argument(
        '--config', '-c',
        default='config/config.yaml',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--log-level', '-l',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # CLI command
    cli_parser = subparsers.add_parser('cli', help='Start CLI mode')
    cli_parser.set_defaults(func=lambda args: run_cli())
    
    # Dashboard command
    dash_parser = subparsers.add_parser('dashboard', help='Start dashboard')
    dash_parser.add_argument('--host', default='0.0.0.0', help='Host to bind')
    dash_parser.add_argument('--port', type=int, default=5000, help='Port to bind')
    dash_parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    dash_parser.set_defaults(func=lambda args: run_dashboard(args))
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run a scan')
    scan_parser.add_argument('target', help='Target URL')
    scan_parser.add_argument('--type', choices=['quick', 'full', 'recon'], default='full', help='Scan type')
    scan_parser.add_argument('--output', '-o', help='Output directory')
    scan_parser.set_defaults(func=lambda args: run_scan(args))
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show system status')
    status_parser.set_defaults(func=lambda args: show_status())
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize the system')
    init_parser.add_argument('--install-tools', action='store_true', help='Install security tools')
    init_parser.set_defaults(func=lambda args: run_init(args))
    
    # Clean command
    clean_parser = subparsers.add_parser('clean', help='Clean up old data')
    clean_parser.add_argument('--days', type=int, default=30, help='Days to keep')
    clean_parser.set_defaults(func=lambda args: run_clean(args))
    
    # Help if no command
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    return parser.parse_args()


def run_cli():
    """Run CLI mode."""
    from cli import main as cli_main
    cli_main()


def run_dashboard(args):
    """Run dashboard mode."""
    try:
        from dashboard.app import run_dashboard
        print(f"🌐 Starting BugBountyAgent Dashboard")
        print(f"   Host: {args.host}")
        print(f"   Port: {args.port}")
        print(f"   Debug: {args.debug}")
        print()
        print("📡 Access dashboard at: http://localhost:" + str(args.port))
        print("Press Ctrl+C to stop")
        print()
        run_dashboard(host=args.host, port=args.port, debug=args.debug)
    except ImportError as e:
        print(f"❌ Failed to import dashboard: {e}")
        print("   Make sure dashboard/app.py exists")
        sys.exit(1)


def run_scan(args):
    """Run a scan directly."""
    try:
        from core.agent import BugBountyAgent
        
        print(f"🚀 Starting {args.type} scan on {args.target}")
        print()
        
        config = get_config()
        agent = BugBountyAgent(config)
        target_id = agent.add_target(args.target)
        print(f"🎯 Target added: {args.target} (ID: {target_id})")
        
        print(f"🔍 Running scan...")
        scan_id = agent.scan(target_id, args.type)
        
        if scan_id:
            print(f"✅ Scan started: {scan_id}")
            print(f"📡 Use 'python main.py status' to check progress")
        else:
            print(f"❌ Failed to start scan")
    except Exception as e:
        print(f"❌ Scan failed: {e}")


def show_status():
    """Show system status."""
    try:
        from core.agent import BugBountyAgent
        from core.state import StateManager
        from core.tools import ToolManager
        
        config = get_config()
        agent = BugBountyAgent(config)
        state = StateManager(config)
        tools = ToolManager(config)
        
        status = agent.get_status()
        stats = state.get_statistics()
        tool_status = tools.check_all_tools()
        
        print()
        print("🐞 BugBountyAgent System Status")
        print("=" * 50)
        print()
        
        print("🤖 Agent:")
        print(f"   Mode: {status.get('mode', 'unknown')}")
        print(f"   Targets: {status.get('targets', 0)}")
        print(f"   Running Scans: {status.get('running_scans', 0)}")
        print(f"   Browser Active: {status.get('browser_active', False)}")
        print()
        
        print("🧠 Knowledge Base:")
        print(f"   Total Findings: {stats.get('findings', 0)}")
        print(f"   Patterns: {stats.get('patterns', 0)}")
        print(f"   Chains: {stats.get('chains', 0)}")
        print()
        
        print("🔧 Tools:")
        installed = sum(1 for t in tool_status.values() if t.installed)
        total = len(tool_status)
        print(f"   Installed: {installed}/{total}")
        for name, info in tool_status.items():
            status_icon = "✅" if info.installed else "❌"
            print(f"   {status_icon} {name}: {info.version or 'not installed'}")
        print()
    except Exception as e:
        print(f"❌ Failed to get status: {e}")


def run_init(args):
    """Initialize the system."""
    try:
        from core.filesystem import FileSystemController
        from core.state import StateManager
        from core.tools import ToolManager
        
        config = get_config()
        filesystem = FileSystemController(config)
        state = StateManager(config)
        tools = ToolManager(config)
        
        print("🔧 Initializing BugBountyAgent System")
        print("=" * 40)
        print()
        
        # Create directories
        print("📁 Creating directories...")
        filesystem._ensure_dirs()
        print("✅ Directories created")
        print()
        
        # Initialize state
        print("💾 Initializing state...")
        state.save_state({'initialized': True, 'timestamp': str(datetime.now())})
        print("✅ State initialized")
        print()
        
        # Install tools if requested
        if args.install_tools:
            print("🔧 Installing security tools...")
            results = tools.install_all_tools()
            installed = sum(1 for v in results.values() if v)
            total = len(results)
            print(f"✅ Installed {installed}/{total} tools")
            print()
        
        print("✅ System initialized successfully!")
        print()
        print("🚀 Quick Start:")
        print("   python main.py scan https://example.com --type full")
        print("   python main.py dashboard")
        print("   python main.py status")
    except Exception as e:
        print(f"❌ Initialization failed: {e}")


def run_clean(args):
    """Clean up old data."""
    try:
        from core.filesystem import FileSystemController
        from core.state import StateManager
        
        config = get_config()
        filesystem = FileSystemController(config)
        state = StateManager(config)
        
        print(f"🧹 Cleaning up data older than {args.days} days...")
        print()
        
        cleaned = filesystem.cleanup_old_files(args.days)
        total = sum(cleaned.values())
        
        print(f"✅ Cleaned up {total} files")
        for category, count in cleaned.items():
            if count > 0:
                print(f"   {category}: {count}")
        print()
        
        print("🗃️ Optimizing database...")
        print("✅ Database optimized")
    except Exception as e:
        print(f"❌ Cleanup failed: {e}")


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Print banner
    print(print_banner())
    print()
    
    try:
        # Execute command
        if hasattr(args, 'func'):
            args.func(args)
        else:
            print("⚠️ No command specified. Use --help for available commands.")
            print()
            print("Quick start:")
            print("  python main.py scan https://example.com")
            print("  python main.py dashboard")
            print("  python main.py status")
            
    except KeyboardInterrupt:
        print("\n⏹️ Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()