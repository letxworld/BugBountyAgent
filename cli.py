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
from core.utils import log_info, log_error, log_warning, get_timestamp


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
        
        # target add
        target_add = target_subparsers.add_parser('add', help='Add a target')
        target_add.add_argument('url', help='Target URL')
        target_add.add_argument('--scope', help='Scope patterns (comma separated)')
        target_add.add_argument('--exclude', help='Exclude patterns (comma separated)')
        target_add.set_defaults(func=self._cmd_target_add)
        
        # target list
        target_list = target_subparsers.add_parser('list', help='List targets')
        target_list.set_defaults(func=self._cmd_target_list)
        
        # target remove
        target_remove = target_subparsers.add_parser('remove', help='Remove a target')
        target_remove.add_argument('target_id', help='Target ID')
        target_remove.set_defaults(func=self._cmd_target_remove)
        
        # target info
        target_info = target_subparsers.add_parser('info', help='Get target info')
        target_info.add_argument('target_id', help='Target ID')
        target_info.set_defaults(func=self._cmd_target_info)
        
        # === Scan Commands ===
        scan_parser = subparsers.add_parser('scan', help='Manage scans')
        scan_subparsers = scan_parser.add_subparsers(dest='scan_action', help='Scan action')
        
        # scan start
        scan_start = scan_subparsers.add_parser('start', help='Start a scan')
        scan_start.add_argument('target_id', help='Target ID')
        scan_start.add_argument('--type', choices=['quick', 'full', 'recon'], default='full', help='Scan type')
        scan_start.set_defaults(func=self._cmd_scan_start)
        
        # scan list
        scan_list = scan_subparsers.add_parser('list', help='List scans')
        scan_list.set_defaults(func=self._cmd_scan_list)
        
        # scan status
        scan_status = scan_subparsers.add_parser('status', help='Get scan status')
        scan_status.add_argument('scan_id', help='Scan ID')
        scan_status.set_defaults(func=self._cmd_scan_status)
        
        # scan stop
        scan_stop = scan_subparsers.add_parser('stop', help='Stop a scan')
        scan_stop.add_argument('scan_id', help='Scan ID')
        scan_stop.set_defaults(func=self._cmd_scan_stop)
        
        # === Findings Commands ===
        findings_parser = subparsers.add_parser('findings', help='Manage findings')
        findings_subparsers = findings_parser.add_subparsers(dest='findings_action', help='Findings action')
        
        # findings list
        findings_list = findings_subparsers.add_parser('list', help='List findings')
        findings_list.add_argument('--target', help='Filter by target')
        findings_list.add_argument('--severity', choices=['critical', 'high', 'medium', 'low', 'info'], help='Filter by severity')
        findings_list.add_argument('--limit', type=int, default=50, help='Limit results')
        findings_list.set_defaults(func=self._cmd_findings_list)
        
        # findings show
        findings_show = findings_subparsers.add_parser('show', help='Show finding details')
        findings_show.add_argument('finding_id', help='Finding ID')
        findings_show.set_defaults(func=self._cmd_findings_show)
        
        # findings export
        findings_export = findings_subparsers.add_parser('export', help='Export findings')
        findings_export.add_argument('--target', help='Filter by target')
        findings_export.add_argument('--format', choices=['json', 'markdown'], default='json', help='Export format')
        findings_export.add_argument('--output', help='Output file path')
        findings_export.set_defaults(func=self._cmd_findings_export)
        
        # === Chains Commands ===
        chains_parser = subparsers.add_parser('chains', help='Manage attack chains')
        chains_subparsers = chains_parser.add_subparsers(dest='chains_action', help='Chains action')
        
        # chains list
        chains_list = chains_subparsers.add_parser('list', help='List chains')
        chains_list.add_argument('--target', help='Filter by target')
        chains_list.set_defaults(func=self._cmd_chains_list)
        
        # === Tools Commands ===
        tools_parser = subparsers.add_parser('tools', help='Manage security tools')
        tools_subparsers = tools_parser.add_subparsers(dest='tools_action', help='Tools action')
        
        # tools list
        tools_list = tools_subparsers.add_parser('list', help='List tools')
        tools_list.set_defaults(func=self._cmd_tools_list)
        
        # tools install
        tools_install = tools_subparsers.add_parser('install', help='Install a tool')
        tools_install.add_argument('tool_name', help='Tool name')
        tools_install.set_defaults(func=self._cmd_tools_install)
        
        # tools install-all
        tools_install_all = tools_subparsers.add_parser('install-all', help='Install all tools')
        tools_install_all.set_defaults(func=self._cmd_tools_install_all)
        
        # === Report Commands ===
        report_parser = subparsers.add_parser('report', help='Generate reports')
        report_subparsers = report_parser.add_subparsers(dest='report_action', help='Report action')
        
        # report generate
        report_generate = report_subparsers.add_parser('generate', help='Generate a report')
        report_generate.add_argument('scan_id', help='Scan ID')
        report_generate.add_argument('--format', choices=['json', 'markdown', 'html'], default='json', help='Report format')
        report_generate.add_argument('--output', help='Output file path')
        report_generate.set_defaults(func=self._cmd_report_generate)
        
        # === Status Command ===
        status_parser = subparsers.add_parser('status', help='Show agent status')
        status_parser.set_defaults(func=self._cmd_status)
        
        # === Dashboard Command ===
        dashboard_parser = subparsers.add_parser('dashboard', help='Start the web dashboard')
        dashboard_parser.add_argument('--host', help='Host to bind')
        dashboard_parser.add_argument('--port', type=int, help='Port to bind')
        dashboard_parser.add_argument('--debug', action='store_true', help='Enable debug mode')
        dashboard_parser.set_defaults(func=self._cmd_dashboard)
        
        # === Config Command ===
        config_parser = subparsers.add_parser('config', help='Show configuration')
        config_parser.set_defaults(func=self._cmd_config)
        
        # === System Command ===
        system_parser = subparsers.add_parser('system', help='System operations')
        system_subparsers = system_parser.add_subparsers(dest='system_action', help='System action')
        
        system_info = system_subparsers.add_parser('info', help='Show system info')
        system_info.set_defaults(func=self._cmd_system_info)
        
        system_clean = system_subparsers.add_parser('clean', help='Clean up old data')
        system_clean.add_argument('--days', type=int, default=30, help='Days to keep')
        system_clean.set_defaults(func=self._cmd_system_clean)
        
        return parser
    
    # ============================================================
    # Target Commands
    # ============================================================
    
    def _cmd_target_add(self, args):
        """Add a target."""
        scope = args.scope.split(',') if args.scope else None
        exclude = args.exclude.split(',') if args.exclude else None
        
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
        print(f"{'ID':<12} {'URL':<40} {'Status':<12} {'Findings':<10}")
        print("-" * 70)
        
        for t in targets:
            status_icon = {
                'pending': '⏳',
                'scanning': '🔄',
                'completed': '✅',
                'failed': '❌'
            }.get(t['status'], '❓')
            print(f"{t['id']:<12} {t['url'][:38]:<40} {status_icon} {t['status']:<10} {t['findings']:<10}")
    
    def _cmd_target_remove(self, args):
        """Remove a target."""
        success = self.agent.remove_target(args.target_id)
        if success:
            print(f"✅ Target removed: {args.target_id}")
        else:
            print(f"❌ Target not found: {args.target_id}")
    
    def _cmd_target_info(self, args):
        """Get target info."""
        target = self.agent.get_target(args.target_id)
        if not target:
            print(f"❌ Target not found: {args.target_id}")
            return
        
        print(f"📋 Target: {target['url']}")
        print(f"   ID: {target['id']}")
        print(f"   Status: {target['status']}")
        print(f"   Findings: {len(target['findings'])}")
        print(f"   Added: {target['added']}")
        print(f"   Completed: {target.get('completed_at', 'N/A')}")
    
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
            print(f"\n📡 Use 'bugbounty scan status {scan_id}' to check progress")
        else:
            print(f"❌ Failed to start scan. Target may be busy or not found.")
    
    def _cmd_scan_list(self, args):
        """List scans."""
        # This would need to retrieve from state
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
        print(f"   Target: {result.target_id}")
        print(f"   Findings: {len(result.findings)}")
        print(f"   Chains: {len(result.chains)}")
        print(f"   Duration: {result.duration:.2f}s")
        print(f"   Report: {result.report_path}")
    
    def _cmd_scan_stop(self, args):
        """Stop a scan."""
        success = self.agent.stop_scan(args.scan_id)
        if success:
            print(f"⏹️ Scan stopped: {args.scan_id}")
        else:
            print(f"❌ Failed to stop scan: {args.scan_id}")
    
    # ============================================================
    # Findings Commands
    # ============================================================
    
    def _cmd_findings_list(self, args):
        """List findings."""
        findings = self.agent.get_findings(args.target)
        
        if args.severity:
            findings = [f for f in findings if f.get('severity') == args.severity]
        
        if not findings:
            print("📭 No findings found.")
            return
        
        print(f"🔍 Findings ({len(findings[:args.limit])}):")
        print("-" * 80)
        print(f"{'ID':<12} {'Severity':<10} {'Title':<35} {'Target':<20}")
        print("-" * 80)
        
        for f in findings[:args.limit]:
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': 'ℹ️'
            }.get(f.get('severity', 'info'), '❓')
            print(f"{f.get('id', '')[:10]:<12} {severity_icon} {f.get('severity', 'info'):<8} {f.get('title', 'Unknown')[:33]:<35} {f.get('target', '')[:18]:<20}")
    
    def _cmd_findings_show(self, args):
        """Show finding details."""
        finding = self.agent.get_finding(args.finding_id)
        
        if not finding:
            print(f"❌ Finding not found: {args.finding_id}")
            return
        
        print(f"🔍 Finding: {finding.get('id')}")
        print(f"   Title: {finding.get('title', 'Unknown')}")
        print(f"   Severity: {finding.get('severity', 'info')}")
        print(f"   Type: {finding.get('type', 'unknown')}")
        print(f"   Target: {finding.get('target', 'N/A')}")
        print(f"   Description: {finding.get('description', 'No description')}")
        print(f"   Remediation: {finding.get('remediation', 'Not provided')}")
        if finding.get('cve_id'):
            print(f"   CVE: {finding.get('cve_id')}")
        if finding.get('cvss_score'):
            print(f"   CVSS: {finding.get('cvss_score')}")
    
    def _cmd_findings_export(self, args):
        """Export findings."""
        findings = self.agent.get_findings(args.target)
        
        if not findings:
            print("📭 No findings to export.")
            return
        
        output_file = args.output or f"findings_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.format}"
        
        if args.format == 'json':
            with open(output_file, 'w') as f:
                json.dump(findings, f, indent=2, default=str)
        else:
            with open(output_file, 'w') as f:
                f.write("# Findings Export\n\n")
                for item in findings:
                    f.write(f"## {item.get('title', 'Unknown')}\n")
                    f.write(f"- **Severity:** {item.get('severity', 'info')}\n")
                    f.write(f"- **Target:** {item.get('target', 'N/A')}\n")
                    f.write(f"- **Description:** {item.get('description', '')}\n\n")
        
        print(f"✅ Exported {len(findings)} findings to: {output_file}")
    
    # ============================================================
    # Chains Commands
    # ============================================================
    
    def _cmd_chains_list(self, args):
        """List chains."""
        print("🔗 Chains:")
        print("-" * 60)
        print("No chains found.")
    
    # ============================================================
    # Tools Commands
    # ============================================================
    
    def _cmd_tools_list(self, args):
        """List tools."""
        tool_status = self.tools.check_all_tools()
        
        print("🔧 Security Tools:")
        print("-" * 60)
        print(f"{'Tool':<15} {'Status':<12} {'Version':<20}")
        print("-" * 60)
        
        for name, info in tool_status.items():
            status = "✅ Installed" if info.installed else "❌ Missing"
            version = info.version or "N/A"
            print(f"{name:<15} {status:<12} {version:<20}")
    
    def _cmd_tools_install(self, args):
        """Install a tool."""
        success = self.tools.install_tool(args.tool_name)
        if success:
            print(f"✅ Tool installed: {args.tool_name}")
        else:
            print(f"❌ Failed to install: {args.tool_name}")
    
    def _cmd_tools_install_all(self, args):
        """Install all tools."""
        results = self.tools.install_all_tools()
        installed = sum(1 for v in results.values() if v)
        total = len(results)
        print(f"✅ Installed {installed}/{total} tools")
    
    # ============================================================
    # Report Commands
    # ============================================================
    
    def _cmd_report_generate(self, args):
        """Generate a report."""
        print(f"📄 Generating report for scan: {args.scan_id}")
        print("   Report generation feature coming soon.")
    
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
        print(f"   Browser Active: {status.get('browser_active', False)}")
        print()
        print("🧠 Knowledge Base:")
        print(f"   Total Findings: {stats.get('findings', 0)}")
        print(f"   Patterns: {stats.get('patterns', 0)}")
        print(f"   Chains: {stats.get('chains', 0)}")
    
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
    
    # ============================================================
    # Config Command
    # ============================================================
    
    def _cmd_config(self, args):
        """Show configuration."""
        config = self.config.get_all()
        print(json.dumps(config, indent=2, default=str))
    
    # ============================================================
    # System Commands
    # ============================================================
    
    def _cmd_system_info(self, args):
        """Show system info."""
        info = self.system.get_system_info()
        
        print("💻 System Information")
        print("=" * 40)
        for key, value in info.items():
            print(f"{key}: {value}")
    
    def _cmd_system_clean(self, args):
        """Clean up old data."""
        cleaned = self.state.cleanup_old_files(args.days)
        total = sum(cleaned.values())
        print(f"🧹 Cleaned up {total} files older than {args.days} days")


# ============================================================
# Main Entry Point
# ============================================================

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