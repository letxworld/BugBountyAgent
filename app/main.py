#!/usr/bin/env python3
"""
BugBountyAgent - Main Entry Point
==================================
This is the main entry point for the application.
Handles initialization, argument parsing, and orchestrates everything.
"""

import sys
import os
import json
import time
import argparse
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import (
    init_app, get_config, log_info, log_error, log_warning, 
    log_debug, print_banner, get_timestamp, get_date
)
from app.agents.bug_hunter import BugHunter
from app.knowledge import KnowledgeBase
from app.system import SystemController
from app.learners import ChainManager


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='BugBountyAgent - AI-Powered Bug Bounty Hunting',
        formatter_class=argparse.RawDescriptionHelpFormatter
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
    
    # === Scan command ===
    scan_parser = subparsers.add_parser('scan', help='Run a scan')
    scan_parser.add_argument('target', help='Target URL or target ID')
    scan_parser.add_argument('--type', choices=['quick', 'full', 'recon'], default='full', help='Scan type')
    scan_parser.add_argument('--output', '-o', help='Output directory for results')
    scan_parser.add_argument('--scope', help='Scope patterns (comma separated)')
    scan_parser.add_argument('--exclude', help='Exclude patterns (comma separated)')
    scan_parser.add_argument('--no-dashboard', action='store_true', help='Don\'t start dashboard')
    
    # === Dashboard command ===
    dashboard_parser = subparsers.add_parser('dashboard', help='Start the web dashboard')
    dashboard_parser.add_argument('--host', default='0.0.0.0', help='Host to bind')
    dashboard_parser.add_argument('--port', type=int, default=5000, help='Port to bind')
    dashboard_parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    # === Status command ===
    status_parser = subparsers.add_parser('status', help='Show agent status')
    
    # === Target command ===
    target_parser = subparsers.add_parser('target', help='Manage targets')
    target_subparsers = target_parser.add_subparsers(dest='target_action')
    
    target_add = target_subparsers.add_parser('add', help='Add a target')
    target_add.add_argument('url', help='Target URL')
    target_add.add_argument('--scope', help='Scope patterns (comma separated)')
    target_add.add_argument('--exclude', help='Exclude patterns (comma separated)')
    
    target_list = target_subparsers.add_parser('list', help='List targets')
    target_remove = target_subparsers.add_parser('remove', help='Remove a target')
    target_remove.add_argument('target_id', help='Target ID')
    
    # === Findings command ===
    findings_parser = subparsers.add_parser('findings', help='Manage findings')
    findings_subparsers = findings_parser.add_subparsers(dest='findings_action')
    
    findings_list = findings_subparsers.add_parser('list', help='List findings')
    findings_list.add_argument('--target', help='Filter by target')
    findings_list.add_argument('--severity', choices=['critical', 'high', 'medium', 'low', 'info'], help='Filter by severity')
    findings_list.add_argument('--limit', type=int, default=50, help='Limit results')
    
    findings_show = findings_subparsers.add_parser('show', help='Show finding details')
    findings_show.add_argument('finding_id', help='Finding ID')
    
    # === Export command ===
    export_parser = subparsers.add_parser('export', help='Export data')
    export_parser.add_argument('--type', choices=['findings', 'chains', 'full'], default='full', help='Data to export')
    export_parser.add_argument('--target', help='Filter by target')
    export_parser.add_argument('--format', choices=['json', 'markdown'], default='json', help='Export format')
    export_parser.add_argument('--output', '-o', help='Output file path')
    
    # === Init command ===
    init_parser = subparsers.add_parser('init', help='Initialize the agent')
    init_parser.add_argument('--force', action='store_true', help='Force re-initialization')
    
    # === Clean command ===
    clean_parser = subparsers.add_parser('clean', help='Clean up old data')
    clean_parser.add_argument('--days', type=int, default=90, help='Days to keep')
    
    return parser.parse_args()


def handle_scan_command(args):
    """Handle scan command."""
    from app.dashboard.app import run_dashboard
    import threading
    
    print(f"🚀 Starting {args.type} scan on {args.target}...")
    
    # Initialize agent
    agent = BugHunter()
    
    # Check if target is an ID or URL
    target_id = args.target
    target = agent.get_target(target_id)
    
    if not target:
        # Add as new target
        scope = args.scope.split(',') if args.scope else None
        exclude = args.exclude.split(',') if args.exclude else None
        target_id = agent.add_target(args.target, scope, exclude)
        print(f"🎯 Target added: {args.target} (ID: {target_id})")
    
    # Start scan
    scan_id = agent.start_scan(target_id, args.type)
    
    if not scan_id:
        print("❌ Failed to start scan.")
        return 1
    
    print(f"✅ Scan started: {scan_id}")
    
    # Check if dashboard should be started
    if not args.no_dashboard:
        print("🌐 Starting dashboard...")
        
        def run_dash():
            try:
                host = get_config('dashboard.host', '0.0.0.0')
                port = get_config('dashboard.port', 5000)
                run_dashboard(host=host, port=port, debug=False)
            except Exception as e:
                print(f"⚠️ Dashboard error: {e}")
        
        dash_thread = threading.Thread(target=run_dash, daemon=True)
        dash_thread.start()
        
        print(f"📊 Dashboard: http://localhost:{get_config('dashboard.port', 5000)}")
    
    print()
    print("📡 Watching scan progress...")
    print("Press Ctrl+C to stop watching (scan continues in background)")
    
    try:
        # Monitor scan progress
        last_status = ""
        while True:
            result = agent.get_scan_result(scan_id)
            if result:
                status = f"Findings: {len(result.findings)}, Chains: {len(result.chains)}, Duration: {result.duration:.1f}s"
                if status != last_status:
                    print(f"   📊 {status}")
                    last_status = status
                if result.summary.get('total_findings', 0) > 0:
                    print(f"   ✅ Scan completed!")
                    print(f"   📄 Report: {result.report_path}")
                    break
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n⏹️ Scan running in background. Check dashboard for progress.")
    
    return 0


def handle_dashboard_command(args):
    """Handle dashboard command."""
    from app.dashboard.app import run_dashboard
    
    print(f"🌐 Starting dashboard at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop")
    
    run_dashboard(host=args.host, port=args.port, debug=args.debug)


def handle_status_command(args):
    """Handle status command."""
    agent = BugHunter()
    kb = KnowledgeBase()
    system = SystemController()
    
    status = agent.get_status()
    stats = kb.get_statistics()
    info = system.get_system_info()
    
    print("🐞 BugBountyAgent Status")
    print("=" * 50)
    print()
    print("🤖 Agent:")
    print(f"   Mode: {status.get('mode', 'unknown')}")
    print(f"   Targets: {status.get('targets', 0)}")
    print(f"   Running Scans: {status.get('running_scans', 0)}")
    print(f"   Browser Active: {status.get('browser_active', False)}")
    print()
    print("🧠 Knowledge Base:")
    print(f"   Total Findings: {stats.get('total_findings', 0)}")
    print(f"   Patterns: {stats.get('total_patterns', 0)}")
    print(f"   Chains: {stats.get('total_chains', 0)}")
    
    if stats.get('severity_counts'):
        print(f"   Severity Distribution:")
        for sev, count in stats['severity_counts'].items():
            print(f"      {sev}: {count}")
    
    print()
    print("💻 System:")
    print(f"   OS: {info.get('os', 'unknown')}")
    print(f"   CPU: {info.get('cpu_percent', 0)}%")
    print(f"   Memory: {info.get('memory_percent', 0)}%")
    disk = info.get('disk_usage', {})
    print(f"   Disk: {disk.get('percent', 0)}% used")
    print(f"   Available: {disk.get('free', 0) // (1024**3)} GB")


def handle_target_command(args):
    """Handle target commands."""
    agent = BugHunter()
    
    if args.target_action == 'add':
        scope = args.scope.split(',') if args.scope else None
        exclude = args.exclude.split(',') if args.exclude else None
        target_id = agent.add_target(args.url, scope, exclude)
        print(f"✅ Target added: {args.url}")
        print(f"   ID: {target_id}")
    
    elif args.target_action == 'list':
        targets = agent.list_targets()
        if not targets:
            print("📭 No targets found.")
            return
        
        print(f"📋 Targets ({len(targets)}):")
        print("-" * 70)
        print(f"{'ID':<12} {'URL':<40} {'Status':<12} {'Findings':<10}")
        print("-" * 70)
        
        for t in targets:
            status_icon = {
                'pending': '⏳',
                'running': '🔄',
                'completed': '✅',
                'failed': '❌'
            }.get(t.status, '❓')
            print(f"{t.id:<12} {t.url[:38]:<40} {status_icon} {t.status:<10} {len(t.findings):<10}")
    
    elif args.target_action == 'remove':
        success = agent.remove_target(args.target_id)
        if success:
            print(f"✅ Target removed: {args.target_id}")
        else:
            print(f"❌ Target not found: {args.target_id}")


def handle_findings_command(args):
    """Handle findings commands."""
    kb = KnowledgeBase()
    
    if args.findings_action == 'list':
        if args.target:
            findings = kb.get_findings_by_target(args.target, args.limit)
        else:
            findings = kb.get_all_findings(args.limit)
        
        if args.severity:
            findings = [f for f in findings if f.severity == args.severity]
        
        if not findings:
            print("📭 No findings found.")
            return
        
        print(f"🔍 Findings ({len(findings)}):")
        print("-" * 80)
        print(f"{'ID':<12} {'Severity':<10} {'Type':<25} {'Target':<20}")
        print("-" * 80)
        
        for f in findings:
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': 'ℹ️'
            }.get(f.severity, '❓')
            print(f"{f.id[:10]:<12} {severity_icon} {f.severity:<8} {f.type[:23]:<25} {f.target[:18]:<20}")
    
    elif args.findings_action == 'show':
        finding = kb.get_finding(args.finding_id)
        if not finding:
            print(f"❌ Finding not found: {args.finding_id}")
            return
        
        print(f"🔍 Finding: {finding.id}")
        print(f"   Type: {finding.type}")
        print(f"   Severity: {finding.severity}")
        print(f"   Target: {finding.target}")
        print(f"   Description: {finding.description}")
        print(f"   CVSS Score: {finding.cvss_score or 'N/A'}")
        print(f"   CVE: {finding.cve_id or 'N/A'}")
        print(f"   URL: {finding.url or 'N/A'}")
        print(f"   Timestamp: {finding.timestamp}")
        print()
        print("📝 Reproduction Steps:")
        print(finding.reproduction_steps or 'N/A')
        print()
        print("🛡️ Remediation:")
        print(finding.remediation or 'N/A')


def handle_export_command(args):
    """Handle export command."""
    kb = KnowledgeBase()
    
    if args.target:
        findings = kb.get_findings_by_target(args.target, 9999)
    else:
        findings = kb.get_all_findings(9999)
    
    if not findings:
        print("📭 No data to export.")
        return
    
    data = {
        'exported_at': get_timestamp(),
        'total': len(findings),
        'findings': [{
            'id': f.id,
            'target': f.target,
            'type': f.type,
            'severity': f.severity,
            'description': f.description,
            'reproduction_steps': f.reproduction_steps,
            'remediation': f.remediation,
            'cvss_score': f.cvss_score,
            'cve_id': f.cve_id,
            'url': f.url,
            'timestamp': f.timestamp
        } for f in findings]
    }
    
    output_file = args.output or f"export_{get_date()}.{args.format}"
    
    if args.format == 'json':
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    elif args.format == 'markdown':
        with open(output_file, 'w') as f:
            f.write("# BugBountyAgent Findings Export\n\n")
            f.write(f"**Exported:** {data['exported_at']}\n")
            f.write(f"**Total Findings:** {data['total']}\n\n")
            
            for item in data['findings']:
                f.write(f"## {item['type']}\n")
                f.write(f"- **ID:** {item['id']}\n")
                f.write(f"- **Severity:** {item['severity']}\n")
                f.write(f"- **Target:** {item['target']}\n")
                f.write(f"- **Description:** {item['description']}\n")
                if item['reproduction_steps']:
                    f.write(f"- **Reproduction Steps:**\n{item['reproduction_steps']}\n")
                if item['remediation']:
                    f.write(f"- **Remediation:** {item['remediation']}\n")
                f.write("\n---\n\n")
    
    print(f"✅ Exported {len(findings)} findings to: {output_file}")


def handle_init_command(args):
    """Handle initialization command."""
    from app.core import create_directories
    
    print("🔧 Initializing BugBountyAgent...")
    
    # Create directories
    create_directories()
    
    # Initialize database
    from app.core import setup_database
    setup_database()
    
    # Check configuration
    config = get_config()
    print(f"✅ Configuration loaded from: {args.config}")
    
    # Check tools
    from app.system import SystemController
    system = SystemController()
    
    tools_to_check = ['nmap', 'nuclei', 'subfinder']
    installed = []
    missing = []
    
    for tool in tools_to_check:
        if system.is_tool_installed(tool):
            installed.append(tool)
        else:
            missing.append(tool)
    
    if installed:
        print(f"✅ Installed tools: {', '.join(installed)}")
    if missing:
        print(f"⚠️ Missing tools: {', '.join(missing)}")
        print("   Run './scripts/install_tools.sh' to install them")
    
    print()
    print("✅ BugBountyAgent initialized successfully!")
    print("   Run 'bugbounty scan <target>' to start hunting")
    print("   Run 'bugbounty dashboard' to open the web interface")


def handle_clean_command(args):
    """Handle clean command."""
    kb = KnowledgeBase()
    
    print(f"🧹 Cleaning up data older than {args.days} days...")
    
    deleted = kb.cleanup_old_data(args.days)
    
    print(f"✅ Cleaned up {deleted} records")


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Initialize app
    init_app(args.config, args.log_level)
    
    # Print banner
    print_banner()
    
    # Route to command handler
    if args.command == 'scan':
        return handle_scan_command(args)
    elif args.command == 'dashboard':
        return handle_dashboard_command(args)
    elif args.command == 'status':
        return handle_status_command(args)
    elif args.command == 'target':
        return handle_target_command(args)
    elif args.command == 'findings':
        return handle_findings_command(args)
    elif args.command == 'export':
        return handle_export_command(args)
    elif args.command == 'init':
        return handle_init_command(args)
    elif args.command == 'clean':
        return handle_clean_command(args)
    else:
        # No command specified, show help
        print("No command specified. Use --help for available commands.")
        print()
        print("Quick start:")
        print("  bugbounty init                     # Initialize the agent")
        print("  bugbounty scan https://example.com # Start a scan")
        print("  bugbounty dashboard                # Open web interface")
        print("  bugbounty status                   # Check agent status")
        return 0


if __name__ == '__main__':
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        print("\n⏹️ Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)