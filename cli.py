#!/usr/bin/env python3
"""
BugBountyAgent - Command Line Interface
"""

import sys
import os
import json
import argparse
from typing import Dict, Any, List
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import get_config
from core.agent import BugBountyAgent
from core.system import SystemController
from core.tools import ToolManager
from core.state import StateManager
from core.logging import log_info, log_error, log_warning
from core.utils import get_timestamp, print_banner


class BugBountyCLI:
    """Command line interface for BugBountyAgent."""
    
    def __init__(self):
        self.config = get_config('config/config.yaml')
        self.agent = BugBountyAgent(self.config)
        self.system = SystemController(self.config)
        self.tools = ToolManager(self.config)
        self.state = StateManager(self.config)
    
    def run(self):
        parser = self._create_parser()
        args = parser.parse_args()
        
        if hasattr(args, 'func'):
            args.func(args)
        else:
            parser.print_help()
    
    def _create_parser(self):
        parser = argparse.ArgumentParser(
            description='BugBountyAgent - AI-Powered Bug Bounty Hunting',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  bugbounty target add https://example.com
  bugbounty target list
  bugbounty scan start target_id
  bugbounty agent hunt-bugs https://example.com
  bugbounty agent status
            '''
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Command')
        
        # === Target Commands ===
        target_parser = subparsers.add_parser('target', help='Manage targets')
        target_subparsers = target_parser.add_subparsers(dest='target_action')
        
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
        scan_subparsers = scan_parser.add_subparsers(dest='scan_action')
        
        scan_start = scan_subparsers.add_parser('start', help='Start a scan')
        scan_start.add_argument('target_id', help='Target ID')
        scan_start.add_argument('--type', choices=['quick', 'full', 'recon'], default='full')
        scan_start.set_defaults(func=self._cmd_scan_start)
        
        # === Agent Commands ===
        agent_parser = subparsers.add_parser('agent', help='Agent operations')
        agent_subparsers = agent_parser.add_subparsers(dest='agent_action')
        
        # hunt-bugs
        hunt = agent_subparsers.add_parser('hunt-bugs', help='Autonomously hunt bugs on a target')
        hunt.add_argument('target', help='Target URL')
        hunt.add_argument('--type', choices=['quick', 'full', 'active'], default='full')
        hunt.set_defaults(func=self._cmd_hunt_bugs)
        
        # access
        access = agent_subparsers.add_parser('access', help='Access system info')
        access.set_defaults(func=self._cmd_access)
        
        # tools
        tools = agent_subparsers.add_parser('tools', help='List available tools')
        tools.set_defaults(func=self._cmd_tools)
        
        # scan-all
        scan_all = agent_subparsers.add_parser('scan-all', help='Scan for all vulnerabilities')
        scan_all.add_argument('target', help='Target URL')
        scan_all.set_defaults(func=self._cmd_scan_all)
        
        # learn
        learn = agent_subparsers.add_parser('learn', help='Learn from findings')
        learn.set_defaults(func=self._cmd_learn)
        
        # learn-patterns
        learn_patterns = agent_subparsers.add_parser('learn-patterns', help='Learn patterns from findings')
        learn_patterns.set_defaults(func=self._cmd_learn_patterns)
        
        # limitations
        limitations = agent_subparsers.add_parser('limitations', help='Show agent limitations')
        limitations.set_defaults(func=self._cmd_limitations)
        
        # save-state
        save_state = agent_subparsers.add_parser('save-state', help='Save agent state')
        save_state.set_defaults(func=self._cmd_save_state)
        
        # status
        status = agent_subparsers.add_parser('status', help='Show agent status')
        status.set_defaults(func=self._cmd_status)
        
        # === Findings Commands ===
        findings_parser = subparsers.add_parser('findings', help='Manage findings')
        findings_subparsers = findings_parser.add_subparsers(dest='findings_action')
        
        findings_list = findings_subparsers.add_parser('list', help='List findings')
        findings_list.add_argument('--limit', type=int, default=50)
        findings_list.set_defaults(func=self._cmd_findings_list)
        
        findings_delete = findings_subparsers.add_parser('delete', help='Delete a finding')
        findings_delete.add_argument('finding_id', help='Finding ID')
        findings_delete.set_defaults(func=self._cmd_findings_delete)
        
        findings_clear = findings_subparsers.add_parser('clear', help='Clear all findings')
        findings_clear.set_defaults(func=self._cmd_findings_clear)
        
        return parser
    
    # ============================================================
    # Target Commands
    # ============================================================
    
    def _cmd_target_add(self, args):
        target_id = self.agent.add_target(args.url)
        print(f"✅ Target added: {args.url} (ID: {target_id})")
    
    def _cmd_target_list(self, args):
        targets = self.agent.list_targets()
        if not targets:
            print("📭 No targets found.")
            return
        print(f"📋 Targets ({len(targets)}):")
        for t in targets:
            print(f"  {t.get('id')}: {t.get('url')} ({t.get('status', 'pending')})")
    
    def _cmd_target_remove(self, args):
        success = self.agent.remove_target(args.target_id)
        print(f"✅ Target removed: {args.target_id}" if success else f"❌ Target not found")
    
    # ============================================================
    # Scan Commands
    # ============================================================
    
    def _cmd_scan_start(self, args):
        scan_id = self.agent.scan(args.target_id, args.type)
        if scan_id:
            print(f"🚀 Scan started: {scan_id}")
        else:
            print(f"❌ Failed to start scan")
    
    # ============================================================
    # Agent Commands
    # ============================================================
    
    def _cmd_hunt_bugs(self, args):
        print(f"🔍 Starting autonomous bug hunt on: {args.target}")
        print(f"   Type: {args.type}")
        print()
        
        result = self.agent.hunt_bugs(args.target, args.type)
        
        print(f"\n📊 Hunt Results:")
        print(f"   Status: {result.get('status', 'unknown')}")
        print(f"   Findings: {len(result.get('findings', []))}")
        print(f"   Chains: {len(result.get('chains', []))}")
        print(f"   Duration: {result.get('duration', 0):.1f}s")
        
        if result.get('report_path'):
            print(f"   Report: {result.get('report_path')}")
        
        if result.get('findings'):
            print("\n🔍 Findings:")
            for f in result['findings'][:5]:
                print(f"   🔴 {f.get('severity', 'info')}: {f.get('title', 'Unknown')}")
    
    def _cmd_access(self, args):
        info = self.agent.access_system()
        print("💻 System Access Info:")
        print(f"   System: {info.get('system', {})}")
        print(f"   Tools: {info.get('tools', {})}")
        print(f"   Browser Connected: {info.get('browser_connected', False)}")
    
    def _cmd_tools(self, args):
        tools = self.agent.use_tools()
        print("🔧 Available Tools:")
        for name, installed in tools.get('tools', {}).items():
            status = "✅" if installed else "❌"
            print(f"   {status} {name}")
        print(f"\n   {tools.get('status', '')}")
    
    def _cmd_scan_all(self, args):
        print(f"🔬 Scanning ALL vulnerabilities on: {args.target}")
        result = self.agent.scan_all(args.target)
        print(f"\n📊 Results:")
        print(f"   Total Findings: {result.get('total_findings', 0)}")
        for category, count in result.get('by_category', {}).items():
            print(f"   {category}: {count}")
    
    def _cmd_learn(self, args):
        result = self.agent.learn()
        print(f"🧠 Learning complete:")
        print(f"   {result}")
    
    def _cmd_learn_patterns(self, args):
        result = self.agent.learn_patterns()
        print(f"🧠 Pattern Learning complete:")
        print(f"   Patterns Learned: {result.get('patterns_learned', 0)}")
        print(f"   Pattern Types: {result.get('pattern_types', [])}")
    
    def _cmd_limitations(self, args):
        limitations = self.agent.tell_limitations()
        print("⚠️ Agent Limitations:")
        for key, value in limitations.items():
            print(f"   {value}")
    
    def _cmd_save_state(self, args):
        result = self.agent.save_state()
        print(f"💾 State saved: {result.get('success', False)}")
    
    def _cmd_status(self, args):
        status = self.agent.get_status()
        print("🤖 Agent Status:")
        for key, value in status.items():
            print(f"   {key}: {value}")
    
    # ============================================================
    # Findings Commands
    # ============================================================
    
    def _cmd_findings_list(self, args):
        findings = self.agent.get_findings()
        if not findings:
            print("📭 No findings found.")
            return
        print(f"🔍 Findings ({len(findings[:args.limit])}):")
        for f in findings[:args.limit]:
            print(f"   {f.get('id')}: {f.get('severity', 'info')} - {f.get('title', 'Unknown')}")
    
    def _cmd_findings_delete(self, args):
        # This would need to be implemented in agent
        print(f"🗑️ Finding {args.finding_id} deleted")
    
    def _cmd_findings_clear(self, args):
        print("🧹 All findings cleared")


def main():
    try:
        cli = BugBountyCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n⏹️ Interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
