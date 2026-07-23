"""
BugBountyAgent - Main Agent Orchestrator
=========================================
The brain that orchestrates everything:
- System access (browser, terminal, filesystem)
- Tool execution (Nmap, Nuclei, Burp, etc.)
- Vulnerability scanning
- Self-learning
- Report generation
"""

import os
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field

from .config import Config
from .browser import BrowserController
from .terminal import TerminalController
from .filesystem import FileSystemController
from .process import ProcessController
from .scanner import Scanner
from .learner import Learner
from .reporter import Reporter
from .utils import get_timestamp, generate_id


@dataclass
class Target:
    """Target being hunted."""
    id: str
    url: str
    status: str  # pending, scanning, completed, failed
    added: str
    findings: List[Dict] = field(default_factory=list)
    chains: List[Dict] = field(default_factory=list)
    completed_at: Optional[str] = None


@dataclass
class ScanResult:
    """Result of a scan."""
    target_id: str
    findings: List[Dict]
    chains: List[Dict]
    duration: float
    report_path: Optional[str] = None


class BugBountyAgent:
    """
    Main agent that orchestrates everything.
    Controls your system like a human bug bounty hunter.
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize the agent."""
        self.config = Config(config_path)
        self.browser = BrowserController(self.config)
        self.terminal = TerminalController(self.config)
        self.filesystem = FileSystemController(self.config)
        self.process = ProcessController(self.config)
        self.scanner = Scanner(self.config, self.browser, self.terminal)
        self.learner = Learner(self.config)
        self.reporter = Reporter(self.config)
        
        self.targets: Dict[str, Target] = {}
        self.scan_results: Dict[str, ScanResult] = {}
        self.running = False
        self.scan_threads: Dict[str, threading.Thread] = {}
        
        self._load_state()
        print(f"🤖 BugBountyAgent initialized (mode: {self.config.get('agent.mode', 'hybrid')})")
    
    # ============================================================
    # Target Management
    # ============================================================
    
    def add_target(self, url: str) -> str:
        """
        Add a target to hunt.
        
        Args:
            url: Target URL (e.g., https://example.com)
            
        Returns:
            str: Target ID
        """
        target_id = generate_id()
        target = Target(
            id=target_id,
            url=url,
            status='pending',
            added=get_timestamp()
        )
        self.targets[target_id] = target
        self._save_state()
        print(f"🎯 Target added: {url} (ID: {target_id})")
        return target_id
    
    def list_targets(self) -> List[Dict]:
        """List all targets."""
        return [
            {
                'id': t.id,
                'url': t.url,
                'status': t.status,
                'findings': len(t.findings),
                'added': t.added
            }
            for t in self.targets.values()
        ]
    
    def get_target(self, target_id: str) -> Optional[Dict]:
        """Get target by ID."""
        target = self.targets.get(target_id)
        if target:
            return {
                'id': target.id,
                'url': target.url,
                'status': target.status,
                'findings': target.findings,
                'chains': target.chains,
                'added': target.added,
                'completed_at': target.completed_at
            }
        return None
    
    # ============================================================
    # Scan Execution
    # ============================================================
    
    def scan(self, target_id: str, scan_type: str = 'full') -> Optional[str]:
        """
        Start a scan on a target.
        
        Args:
            target_id: Target ID
            scan_type: 'quick', 'full', 'recon'
            
        Returns:
            Optional[str]: Scan ID or None
        """
        target = self.targets.get(target_id)
        if not target:
            print(f"❌ Target not found: {target_id}")
            return None
        
        if target.status == 'scanning':
            print(f"⏳ Target already scanning: {target_id}")
            return None
        
        scan_id = generate_id()
        target.status = 'scanning'
        self._save_state()
        
        print(f"🚀 Starting {scan_type} scan on {target.url}")
        
        # Run scan in background thread
        thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, target_id, scan_type)
        )
        thread.daemon = True
        thread.start()
        self.scan_threads[scan_id] = thread
        
        return scan_id
    
    def _run_scan(self, scan_id: str, target_id: str, scan_type: str):
        """Run the scan in background."""
        target = self.targets.get(target_id)
        start_time = time.time()
        findings = []
        chains = []
        
        try:
            print(f"🔍 Phase 1: Reconnaissance on {target.url}")
            recon_data = self.scanner.reconnaissance(target.url)
            if recon_data:
                print(f"   ✅ Found {len(recon_data.get('subdomains', []))} subdomains")
                print(f"   ✅ Found {len(recon_data.get('ports', []))} open ports")
            
            print(f"🔬 Phase 2: Vulnerability Scanning on {target.url}")
            vuln_findings = self.scanner.scan_vulnerabilities(target.url, scan_type)
            findings.extend(vuln_findings)
            if vuln_findings:
                print(f"   ✅ Found {len(vuln_findings)} vulnerabilities")
                for f in vuln_findings[:3]:
                    print(f"      🔴 {f.get('severity', 'info')}: {f.get('title', 'Unknown')}")
            
            print(f"🧠 Phase 3: Learning from findings")
            self.learner.learn(findings)
            
            print(f"🔗 Phase 4: Building attack chains")
            chains = self.learner.build_chains(target.url, findings)
            if chains:
                print(f"   ✅ Built {len(chains)} attack chains")
            
            print(f"📄 Phase 5: Generating report")
            duration = time.time() - start_time
            report_path = self.reporter.generate(target.url, findings, chains)
            
            # Update target
            target.status = 'completed'
            target.findings = findings
            target.chains = chains
            target.completed_at = get_timestamp()
            self._save_state()
            
            # Save result
            self.scan_results[scan_id] = ScanResult(
                target_id=target_id,
                findings=findings,
                chains=chains,
                duration=duration,
                report_path=report_path
            )
            
            print(f"✅ Scan complete! Found {len(findings)} vulnerabilities in {duration:.1f}s")
            print(f"📄 Report saved: {report_path}")
            
        except Exception as e:
            print(f"❌ Scan failed: {e}")
            target.status = 'failed'
            self._save_state()
        
        finally:
            if scan_id in self.scan_threads:
                del self.scan_threads[scan_id]
    
    # ============================================================
    # System Access
    # ============================================================
    
    def system_access(self) -> Dict[str, Any]:
        """
        Get system access capabilities.
        
        Returns:
            Dict: Access capabilities
        """
        return {
            'browser': {
                'available': True,
                'controlled': self.browser.is_connected(),
                'can_navigate': True,
                'can_click': True,
                'can_type': True
            },
            'terminal': {
                'available': True,
                'can_run_commands': True,
                'can_install_tools': True
            },
            'filesystem': {
                'available': True,
                'can_read': True,
                'can_write': True,
                'can_create_dirs': True
            },
            'process': {
                'available': True,
                'can_start': True,
                'can_stop': True,
                'can_monitor': True
            }
        }
    
    # ============================================================
    # Dashboard Integration
    # ============================================================
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status for dashboard."""
        return {
            'status': 'running' if self.running else 'idle',
            'mode': self.config.get('agent.mode', 'hybrid'),
            'targets': len(self.targets),
            'running_scans': len(self.scan_threads),
            'total_findings': sum(len(t.findings) for t in self.targets.values()),
            'system': self.system_access(),
            'timestamp': get_timestamp()
        }
    
    def get_findings(self, target_id: Optional[str] = None) -> List[Dict]:
        """Get all findings."""
        if target_id:
            target = self.targets.get(target_id)
            return target.findings if target else []
        
        all_findings = []
        for target in self.targets.values():
            all_findings.extend(target.findings)
        return all_findings
    
    # ============================================================
    # State Management
    # ============================================================
    
    def _load_state(self):
        """Load state from disk."""
        try:
            with open('data/state.json', 'r') as f:
                data = json.load(f)
                for t in data.get('targets', []):
                    target = Target(
                        id=t['id'],
                        url=t['url'],
                        status=t['status'],
                        added=t['added'],
                        findings=t.get('findings', []),
                        chains=t.get('chains', []),
                        completed_at=t.get('completed_at')
                    )
                    self.targets[target.id] = target
            print(f"📂 Loaded {len(self.targets)} targets from state")
        except:
            pass
    
    def _save_state(self):
        """Save state to disk."""
        try:
            os.makedirs('data', exist_ok=True)
            data = {
                'targets': [
                    {
                        'id': t.id,
                        'url': t.url,
                        'status': t.status,
                        'added': t.added,
                        'findings': t.findings,
                        'chains': t.chains,
                        'completed_at': t.completed_at
                    }
                    for t in self.targets.values()
                ]
            }
            with open('data/state.json', 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"⚠️ Failed to save state: {e}")
    
    # ============================================================
    # Cleanup
    # ============================================================
    
    def cleanup(self):
        """Clean up resources."""
        self.browser.disconnect()
        self.process.stop_all()
        print("🧹 Agent cleaned up")