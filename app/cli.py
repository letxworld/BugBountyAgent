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
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import init_app, get_config, log_info, log_error, log_warning
from app.agents.bug_hunter import BugHunter
from app.knowledge import KnowledgeBase
from app.system import SystemController


class BugBountyCLI:
    """Command line interface for BugBountyAgent."""
    
    def __init__(self):
        """Initialize CLI."""
        self.agent = BugHunter()
        self.kb = KnowledgeBase()
        self.system = SystemController()
    
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
        scan_start.add_argument('--type', choices=['quick', 'full', 'custom'], default='full', help='Scan type')
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
        findings_export.add_argument('--format', choices=['json', 'csv', 'markdown'], default='json', help='Export format')
        findings_export.add_argument('--output', help='Output file path')
        findings_export.set_defaults(func=self._cmd_findings_export)
        
        # === Chains Commands ===
        chains_parser = subparsers.add_parser('chains', help='Manage attack chains')
        chains_subparsers = chains_parser.add_subparsers(dest='chains_action', help='Chains action')
        
        # chains list
        chains_list = chains_subparsers.add_parser('list', help='List chains')
        chains_list.add_argument('--target', help='Filter by target')
        chains_list.set_defaults(func=self._cmd_chains_list)
        
        # chains show
        chains_show = chains_subparsers.add_parser('show', help='Show chain details')
        chains_show.add_argument('chain_id', help='Chain ID')
        chains_show.set_defaults(func=self._cmd_chains_show)
        
        # === Report Commands ===
        report_parser = subparsers.add_parser('report', help='Generate reports')
        report_subparsers = report_parser.add_subparsers(dest='report_action', help='Report action')
        
        # report generate
        report_generate = report_subparsers.add_parser('generate', help='Generate a report')
        report_generate.add_argument('scan_id', help='Scan ID')
        report_generate.add_argument('--format', choices=['json', 'html', 'pdf'], default='json', help='Report format')
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
        
        return parser
    
    # ============================================================
    # Target Commands
    # ============================================================
    
    def _cmd_target_add(self, args):
        """Add a target."""
        scope = args.scope.split(',') if args.scope else None
        exclude = args.exclude.split(',') if args.exclude else None
        
        target_id = self.agent.add_target(args.url, scope, exclude)
        print(f"✅ Target added: {args.url}")
        print(f"   ID: {target_id}")
    
    def _cmd_target_list(self, args):
        """List targets."""
        targets = self.agent.list_targets()
        
        if not targets:
            print("📭 No targets found.")
            return
        
        print(f"📋 Targets ({len(targets)}):")
        print("-" * 60)
        print(f"{'ID':<12} {'URL':<40} {'Status':<12}")
        print("-" * 60)
        
        for t in targets:
            status_icon = {
                'pending': '⏳',
                'running': '🔄',
                'completed': '✅',
                'failed': '❌'
            }.get(t.status, '❓')
            print(f"{t.id:<12} {t.url[:38]:<40} {status_icon} {t.status}")
    
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
        
        print(f"📋 Target: {target.url}")
        print(f"   ID: {target.id}")
        print(f"   Status: {target.status}")
        print(f"   Started: {target.start_time}")
        print(f"   Ended: {target.end_time or 'N/A'}")
        print(f"   Findings: {len(target.findings)}")
        print(f"   Scope: {', '.join(target.scope) if target.scope else 'N/A'}")
        print(f"   Exclude: {', '.join(target.exclude) if target.exclude else 'N/A'}")
    
    # ============================================================
    # Scan Commands
    # ============================================================
    
    def _cmd_scan_start(self, args):
        """Start a scan."""
        print(f"🚀 Starting {args.type} scan on target {args.target_id}...")
        scan_id = self.agent.start_scan(args.target_id, args.type)
        
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
        # Get scan results
        scans = []
        # This would need to be implemented in the agent
        
        if not scans:
            print("📭 No scans found.")
            return
        
        print(f"📋 Scans:")
        print("-" * 60)
    
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
        print()
        print("📈 Summary:")
        summary = result.summary
        for key, value in summary.items():
            print(f"   {key}: {value}")
    
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
        if args.target:
            findings = self.kb.get_findings_by_target(args.target, args.limit)
        else:
            findings = self.kb.get_all_findings(args.limit)
        
        # Filter by severity
        if args.severity:
            findings = [f for f in findings if f.severity == args.severity]
        
        if not findings:
            print("📭 No findings found.")
            return
        
        print(f"🔍 Findings ({len(findings)}):")
        print("-" * 80)
        print(f"{'ID':<12} {'Severity':<10} {'Type':<25} {'Target':<20}")
        print("-" * 80)
        
        for f in findings[:args.limit]:
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': 'ℹ️'
            }.get(f.severity, '❓')
            print(f"{f.id[:10]:<12} {severity_icon} {f.severity:<8} {f.type[:23]:<25} {f.target[:18]:<20}")
    
    def _cmd_findings_show(self, args):
        """Show finding details."""
        finding = self.kb.get_finding(args.finding_id)
        
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
    
    def _cmd_findings_export(self, args):
        """Export findings."""
        if args.target:
            findings = self.kb.get_findings_by_target(args.target, 9999)
        else:
            findings = self.kb.get_all_findings(9999)
        
        if not findings:
            print("📭 No findings to export.")
            return
        
        # Convert to dict
        data = [{
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
        
        output_file = args.output or f"findings_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.format}"
        
        if args.format == 'json':
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        elif args.format == 'csv':
            import csv
            if data:
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)
        elif args.format == 'markdown':
            with open(output_file, 'w') as f:
                f.write("# Findings Export\n\n")
                for item in data:
                    f.write(f"## {item['type']}\n")
                    f.write(f"- **Severity:** {item['severity']}\n")
                    f.write(f"- **Target:** {item['target']}\n")
                    f.write(f"- **Description:** {item['description']}\n\n")
        
        print(f"✅ Exported {len(data)} findings to: {output_file}")
    
    # ============================================================
    # Chains Commands
    # ============================================================
    
    def _cmd_chains_list(self, args):
        """List chains."""
        if args.target:
            chains = self.kb.get_chains_by_target(args.target)
        else:
            chains = []
            # Get all chains from all targets
        
        if not chains:
            print("📭 No chains found.")
            return
        
        print(f"🔗 Chains ({len(chains)}):")
        print("-" * 70)
        print(f"{'ID':<12} {'Name':<25} {'Severity':<10} {'Steps':<6} {'Completed'}")
        print("-" * 70)
        
        for c in chains:
            status = '✅' if c.completed else '⏳'
            print(f"{c.id[:10]:<12} {c.name[:23]:<25} {c.severity:<10} {len(c.steps):<6} {status}")
    
    def _cmd_chains_show(self, args):
        """Show chain details."""
        # Get chain from knowledge base
        chains = self.kb.get_chains_by_target('')  # This needs to be fixed
    
    # ============================================================
    # Report Commands
    # ============================================================
    
    def _cmd_report_generate(self, args):
        """Generate a report."""
        print(f"📄 Generating report for scan: {args.scan_id}")
        # This would need to be implemented
    
    # ============================================================
    # Status Command
    # ============================================================
    
    def _cmd_status(self, args):
        """Show agent status."""
        status = self.agent.get_status()
        system_info = self.system.get_system_info()
        kb_stats = self.kb.get_statistics()
        
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
        print(f"   Findings: {kb_stats.get('total_findings', 0)}")
        print(f"   Patterns: {kb_stats.get('total_patterns', 0)}")
        print(f"   Chains: {kb_stats.get('total_chains', 0)}")
        print()
        print("💻 System:")
        print(f"   OS: {system_info.get('os', 'unknown')}")
        print(f"   CPU: {system_info.get('cpu_percent', 0)}%")
        print(f"   Memory: {system_info.get('memory_percent', 0)}%")
        print(f"   Disk: {system_info.get('disk_usage', {}).get('percent', 0)}%")
    
    # ============================================================
    # Dashboard Command
    # ============================================================
    
    def _cmd_dashboard(self, args):
        """Start the web dashboard."""
        from app.dashboard.app import run_dashboard
        
        host = args.host or get_config('dashboard.host', '0.0.0.0')
        port = args.port or get_config('dashboard.port', 5000)
        debug = args.debug or get_config('dashboard.debug', True)
        
        print(f"🌐 Starting dashboard at http://{host}:{port}")
        print("Press Ctrl+C to stop")
        
        run_dashboard(host=host, port=port, debug=debug)
    
    # ============================================================
    # Config Command
    # ============================================================
    
    def _cmd_config(self, args):
        """Show configuration."""
        config = get_config()
        
        # Remove sensitive data
        sensitive_keys = ['api_key', 'password', 'secret', 'token']
        def clean_config(obj):
            if isinstance(obj, dict):
                return {k: '***' if any(s in k.lower() for s in sensitive_keys) else clean_config(v) 
                        for k, v in obj.items()}
            return obj
        
        cleaned = clean_config(config)
        print(json.dumps(cleaned, indent=2, default=str))


# ============================================================
# Main Entry Point
# ============================================================

def main():
    """Main entry point for CLI."""
    try:
        # Initialize app
        init_app()
        
        # Run CLI
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