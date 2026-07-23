#!/usr/bin/env python3
"""
BugBountyAgent - Command Line Interface
========================================
CLI for controlling the agent, managing targets, and running scans.
"""

import sys
import os
import json
import argparse
from typing import Dict, Any, List, Optional
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import Config, get_config
from core.agent import BugBountyAgent
from core.system import SystemController
from core.tools import ToolManager
from core.state import StateManager
from core.logging import log_info, log_error, log_warning
from core.utils import get_timestamp, print_banner


class BugBountyCLI:
    """Command line interface for BugBountyAgent."""
    
    def __init__(self):
        """Initialize CLI."""
        self.config = get_config('config/config.yaml')
        self.agent = BugBountyAgent(self.config)
        self.system = SystemController(self.config)
        self.tools = ToolManager(self.config)
        self.state = StateManager(self.config)
    
    def run(self):
        """Run the CLI."""
        parser = self._create_parser()
        args = parser.parse_args()
        
        if hasattr(args, 'func'):
            args.func(args)
        else:
            parser.print_help()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            description='BugBountyAgent - AI-Powered Bug Bounty Hunting',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  bugbounty target add https://example.com
  bugbounty target list
  bugbounty scan start target_id
  bugbounty scan list
  bugbounty findings list --severity critical
  bugbounty chains list --target example.com
  bugbounty report generate scan_id
  bugbounty status
  bugbounty dashboard
            '''
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # === Target Commands ===
        target_parser = subparsers.add_parser('target', help='Manage targets')
        target_subparsers = target_parser.add_subparsers(dest='target_action', help='Target action')
        
        target_add = target_subparsers.add_parser('add', help='Add a target')
        target_add.add_argument('url', help='Target URL')
        target_add.set_defaults(func=self._cmd_target_add)
        
        target_list = target_subparsers.add_parser('list', help='List targets')
        target_list.set_defaults(func=self._cmd_target_list)
        
        target_remove = target_subparsers.add_parser('remove', help='Remove a target')
        target_remove.add_argument('target_id', help='Target ID')
        target_remove.set_defaults(func=self._cmd_target_remove)
        
        # === Scan Commands ===
        scan_parser = subparsers.add_parser('scan', help='Manage scans')
        scan_subparsers = scan_parser.add_subparsers(dest='scan_action', help='Scan action')
        
        scan_start = scan_subparsers.add_parser('start', help='Start a scan')
        scan_start.add_argument('target_id', help='Target ID')
        scan_start.add_argument('--type', choices=['quick', 'full', 'recon'], default='full', help='Scan type')
        scan_start.set_defaults(func=self._cmd_scan_start)
        
        scan_list = scan_subparsers.add_parser('list', help='List scans')
        scan_list.set_defaults(func=self._cmd_scan_list)
        
        scan_status = scan_subparsers.add_parser('status', help='Get scan status')
        scan_status.add_argument('scan_id', help='Scan ID')
        scan_status.set_defaults(func=self._cmd_scan_status)
        
        # === Findings Commands ===
        findings_parser = subparsers.add_parser('findings', help='Manage findings')
        findings_subparsers = findings_parser.add_subparsers(dest='findings_action', help='Findings action')
        
        findings_list = findings_subparsers.add_parser('list', help='List findings')
        findings_list.add_argument('--limit', type=int, default=50, help='Limit results')
        findings_list.set_defaults(func=self._cmd_findings_list)
        
        # === Status Command ===
        status_parser = subparsers.add_parser('status', help='Show agent status')
        status_parser.set_defaults(func=self._cmd_status)
        
        # === Agent Commands ===
        agent_parser = subparsers.add_parser('agent', help='Agent operations')
        agent_subparsers = agent_parser.add_subparsers(dest='agent_action', help='Agent action')
        
        agent_access = agent_subparsers.add_parser('access', help='Access local system and tool status')
        agent_access.set_defaults(func=self._cmd_agent_access)
        
        agent_tools = agent_subparsers.add_parser('tools', help='Check and optionally install tools')
        agent_tools.add_argument('--install-missing', action='store_true', help='Install missing tools')
        agent_tools.set_defaults(func=self._cmd_agent_tools)
        
        agent_scan_all = agent_subparsers.add_parser('scan-all', help='Scan all saved targets')
        agent_scan_all.add_argument('--type', choices=['quick', 'full', 'recon'], default='full', help='Scan type')
        agent_scan_all.set_defaults(func=self._cmd_agent_scan_all)
        
        agent_learn = agent_subparsers.add_parser('learn', help='Learn from past findings')
        agent_learn.add_argument('--target-id', help='Target ID to learn from')
        agent_learn.set_defaults(func=self._cmd_agent_learn)
        
        agent_learn_patterns = agent_subparsers.add_parser('learn-patterns', help='Learn vulnerability patterns')
        agent_learn_patterns.add_argument('--target-id', help='Target ID to learn patterns from')
        agent_learn_patterns.set_defaults(func=self._cmd_agent_learn_patterns)
        
        agent_limitations = agent_subparsers.add_parser('limitations', help='Show agent limitations')
        agent_limitations.set_defaults(func=self._cmd_agent_limitations)
        
        agent_save_state = agent_subparsers.add_parser('save-state', help='Save current agent state')
        agent_save_state.add_argument('--message', help='Optional message to store in state', default='Saved by CLI')
        agent_save_state.set_defaults(func=self._cmd_agent_save_state)
        
        # === Dashboard Command ===
        dashboard_parser = subparsers.add_parser('dashboard', help='Start the web dashboard')
        dashboard_parser.add_argument('--host', help='Host to bind')
        dashboard_parser.add_argument('--port', type=int, help='Port to bind')
        dashboard_parser.add_argument('--debug', action='store_true', help='Enable debug mode')
        dashboard_parser.set_defaults(func=self._cmd_dashboard)
        
        return parser
    
    # ============================================================
    # Target Commands
    # ============================================================
    
    def _cmd_target_add(self, args):
        """Add a target."""
        target_id = self.agent.add_target(args.url)
        print(f"✅ Target added: {args.url}")
        print(f"   ID: {target_id}")
    
    def _cmd_target_list(self, args):
        """List targets."""
        targets = self.agent.list_targets()
        
        if not targets:
            print("📭 No targets found.")
            return
        
        print(f"📋 Targets ({len(targets)}):")
        print("-" * 70)
        print(f"{'ID':<12} {'URL':<40} {'Status':<12}")
        print("-" * 70)
        
        for t in targets:
            status_icon = {
                'pending': '⏳',
                'scanning': '🔄',
                'completed': '✅',
                'failed': '❌'
            }.get(t.get('status', 'pending'), '❓')
            print(f"{t.get('id', '')[:10]:<12} {t.get('url', '')[:38]:<40} {status_icon} {t.get('status', 'pending')}")
    
    def _cmd_target_remove(self, args):
        """Remove a target."""
        success = self.agent.remove_target(args.target_id)
        if success:
            print(f"✅ Target removed: {args.target_id}")
        else:
            print(f"❌ Target not found: {args.target_id}")
    
    # ============================================================
    # Scan Commands
    # ============================================================
    
    def _cmd_scan_start(self, args):
        """Start a scan."""
        print(f"🚀 Starting {args.type} scan on target {args.target_id}...")
        scan_id = self.agent.scan(args.target_id, args.type)
        
        if scan_id:
            print(f"✅ Scan started!")
            print(f"   Scan ID: {scan_id}")
            print(f"   Target ID: {args.target_id}")
            print(f"   Type: {args.type}")
        else:
            print(f"❌ Failed to start scan. Target may be busy or not found.")
    
    def _cmd_scan_list(self, args):
        """List scans."""
        print("📋 Scans:")
        print("-" * 60)
        print("No scans found.")
    
    def _cmd_scan_status(self, args):
        """Get scan status."""
        result = self.agent.get_scan_result(args.scan_id)
        
        if not result:
            print(f"❌ Scan not found: {args.scan_id}")
            return
        
        print(f"📊 Scan: {args.scan_id}")
        print(f"   Target: {result.get('target_id', 'unknown')}")
        print(f"   Findings: {len(result.get('findings', []))}")
        print(f"   Duration: {result.get('duration', 0):.2f}s")
    
    # ============================================================
    # Findings Commands
    # ============================================================
    
    def _cmd_findings_list(self, args):
        """List findings."""
        findings = self.agent.get_findings()
        
        if not findings:
            print("📭 No findings found.")
            return
        
        print(f"🔍 Findings ({len(findings[:args.limit])}):")
        print("-" * 80)
        print(f"{'ID':<12} {'Severity':<10} {'Title':<40}")
        print("-" * 80)
        
        for f in findings[:args.limit]:
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': 'ℹ️'
            }.get(f.get('severity', 'info'), '❓')
            print(f"{f.get('id', '')[:10]:<12} {severity_icon} {f.get('severity', 'info'):<8} {f.get('title', 'Unknown')[:38]:<40}")
    
    # ============================================================
    # Status Command
    # ============================================================
    
    def _cmd_status(self, args):
        """Show agent status."""
        status = self.agent.get_status()
        stats = self.state.get_statistics()
        
        print("🐞 BugBountyAgent Status")
        print("=" * 50)
        print()
        print("🤖 Agent:")
        print(f"   Mode: {status.get('mode', 'unknown')}")
        print(f"   Targets: {status.get('targets', 0)}")
        print(f"   Running Scans: {status.get('running_scans', 0)}")
        print(f"   Total Findings: {status.get('total_findings', 0)}")
        print()
        print("🧠 Knowledge Base:")
        print(f"   Total Findings: {stats.get('findings', 0)}")
        print(f"   Chains: {stats.get('chains', 0)}")
        print(f"   Scans: {stats.get('scans', 0)}")

    def _cmd_agent_access(self, args):
        """Show system access information."""
        result = self.agent.access_system()
        print("🔌 System Access")
        print(json.dumps(result, indent=2))

    def _cmd_agent_tools(self, args):
        """Check tool status and install missing tools."""
        result = self.agent.use_tools(install_missing=args.install_missing)
        print("🧰 Tool Status")
        print(json.dumps(result, indent=2))

    def _cmd_agent_scan_all(self, args):
        """Scan all saved targets."""
        result = self.agent.scan_all(scan_type=args.type)
        print("🚀 Scan All")
        print(json.dumps(result, indent=2))

    def _cmd_agent_learn(self, args):
        """Learn from past findings."""
        result = self.agent.learn(target_id=args.target_id)
        print("🧠 Learn")
        print(json.dumps(result, indent=2))

    def _cmd_agent_learn_patterns(self, args):
        """Learn vulnerability patterns."""
        result = self.agent.learn_patterns(target_id=args.target_id)
        print("📘 Learn Patterns")
        print(json.dumps(result, indent=2))

    def _cmd_agent_limitations(self, args):
        """Show agent limitations."""
        result = self.agent.tell_limitations()
        print("⚠️ Agent Limitations")
        print(json.dumps(result, indent=2))

    def _cmd_agent_save_state(self, args):
        """Save current agent state."""
        state = {
            'timestamp': get_timestamp(),
            'message': args.message,
            'targets': self.agent.list_targets()
        }
        success = self.agent.save_state(state)
        print("💾 Save State")
        print(f"   Success: {success}")
        print()
        print("🧠 Knowledge Base:")
        print(f"   Total Findings: {stats.get('findings', 0)}")
        print(f"   Chains: {stats.get('chains', 0)}")
        print(f"   Scans: {stats.get('scans', 0)}")
    
    # ============================================================
    # Dashboard Command
    # ============================================================
    
    def _cmd_dashboard(self, args):
        """Start the web dashboard."""
        from dashboard.app import run_dashboard
        
        host = args.host or self.config.get('dashboard.host', '0.0.0.0')
        port = args.port or self.config.get('dashboard.port', 5000)
        debug = args.debug or self.config.get('dashboard.debug', True)
        
        print(f"🌐 Starting dashboard at http://{host}:{port}")
        print("Press Ctrl+C to stop")
        
        run_dashboard(host=host, port=port, debug=debug)


def main():
    """Main entry point for CLI."""
    try:
        cli = BugBountyCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n⏹️ Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
