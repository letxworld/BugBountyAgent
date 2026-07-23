"""
BugBountyAgent - Main Agent Orchestrator
=========================================
The brain that orchestrates everything.
"""

import os
import json
import time
import threading
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urlparse

from .config import Config
from .state import StateManager
from .system import SystemController
from .scanner import Scanner
from .tools import ToolManager
from .brain import Brain
from .learner import Learner
from .reporter import Reporter
from .utils import get_timestamp, generate_id
from .logging import log_info, log_error, log_warning, log_debug


class BugBountyAgent:
    """
    Main agent that orchestrates everything.
    Controls your system like a human bug bounty hunter.
    """
    
    def __init__(self, config: Config):
        """Initialize the agent."""
        self.config = config
        self.state = StateManager(config)
        self.system = SystemController(config)
        self.scanner = Scanner(config, self.system.browser, self.system.terminal)
        self.tools = ToolManager(config)
        self.brain = Brain(config)
        self.learner = Learner(config)
        self.reporter = Reporter(config)
        
        self.targets: Dict[str, Dict] = {}
        self.scan_results: Dict[str, Dict] = {}
        self.running_scans: Dict[str, threading.Thread] = {}
        self._socketio = None
        
        self._load_state()
        log_info("🤖 BugBountyAgent initialized")
    
    def set_socketio(self, socketio_instance):
        """Set SocketIO instance for real-time updates."""
        self._socketio = socketio_instance
    
    def _emit_log(self, level: str, message: str):
        """Emit log to dashboard via SocketIO."""
        if self._socketio:
            try:
                self._socketio.emit('log_message', {
                    'level': level,
                    'message': message,
                    'timestamp': get_timestamp()
                })
            except:
                pass
    
    # ============================================================
    # Target Management
    # ============================================================
    
    def add_target(self, url: str) -> str:
        """Add a target to hunt."""
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        target_id = generate_id()
        target = {
            'id': target_id,
            'url': url,
            'status': 'pending',
            'added': get_timestamp(),
            'findings': [],
            'chains': []
        }
        
        self.targets[target_id] = target
        self.state.save_target(target)
        
        log_info(f"🎯 Target added: {url} (ID: {target_id})")
        self._emit_log('success', f"🎯 Target added: {url}")
        return target_id
    
    def list_targets(self) -> List[Dict]:
        """List all targets."""
        return list(self.targets.values())
    
    def get_target(self, target_id: str) -> Optional[Dict]:
        """Get target by ID."""
        return self.targets.get(target_id)
    
    def remove_target(self, target_id: str) -> bool:
        """Remove a target."""
        if target_id in self.targets:
            del self.targets[target_id]
            self.state.delete_target(target_id)
            log_info(f"🗑️ Target removed: {target_id}")
            self._emit_log('info', f"🗑️ Target removed: {target_id}")
            return True
        return False
    
    # ============================================================
    # Scan Execution
    # ============================================================
    
    def scan(self, target_id: str, scan_type: str = 'full') -> Optional[str]:
        """Start a scan on a target."""
        target = self.targets.get(target_id)
        if not target:
            log_error(f"❌ Target not found: {target_id}")
            self._emit_log('error', f"❌ Target not found: {target_id}")
            return None
        
        if target.get('status') == 'scanning':
            log_warning(f"⏳ Target already scanning: {target_id}")
            self._emit_log('warning', f"⏳ Target already scanning: {target_id}")
            return None
        
        scan_id = generate_id()
        target['status'] = 'scanning'
        self.state.save_target(target)
        
        log_info(f"🚀 Starting {scan_type} scan on {target['url']}")
        self._emit_log('info', f"🚀 Starting {scan_type} scan on {target['url']}")
        
        thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, target_id, scan_type)
        )
        thread.daemon = True
        thread.start()
        self.running_scans[scan_id] = thread
        
        scan_record = {
            'id': scan_id,
            'target_id': target_id,
            'scan_type': scan_type,
            'status': 'running',
            'start_time': get_timestamp(),
            'findings_count': 0
        }
        self.state.save_scan(scan_record)
        
        return scan_id
    
    def _run_scan(self, scan_id: str, target_id: str, scan_type: str):
        """Run the scan in background."""
        target = self.targets.get(target_id)
        start_time = time.time()
        findings = []
        chains = []
        
        try:
            url = target['url']
            
            # Phase 1: Reconnaissance
            log_info(f"🔍 Phase 1: Reconnaissance on {url}")
            self._emit_log('info', f"🔍 Phase 1: Reconnaissance on {url}")
            
            recon_data = self.scanner.reconnaissance(url)
            if recon_data:
                subdomains = recon_data.get('subdomains', [])
                ports = recon_data.get('ports', [])
                log_info(f"   ✅ Found {len(subdomains)} subdomains")
                log_info(f"   ✅ Found {len(ports)} open ports")
                self._emit_log('info', f"   ✅ Found {len(subdomains)} subdomains, {len(ports)} open ports")
            
            # Phase 2: Vulnerability Scanning
            log_info(f"🔬 Phase 2: Vulnerability Scanning on {url}")
            self._emit_log('info', f"🔬 Phase 2: Vulnerability Scanning on {url}")
            
            vuln_findings = self.scanner.scan_vulnerabilities(url, scan_type)
            findings.extend(vuln_findings)
            
            if vuln_findings:
                log_info(f"   ✅ Found {len(vuln_findings)} vulnerabilities")
                self._emit_log('info', f"   ✅ Found {len(vuln_findings)} vulnerabilities")
                for f in vuln_findings[:3]:
                    log_info(f"      🔴 {f.get('severity', 'info')}: {f.get('title', 'Unknown')}")
                    self._emit_log('attack', f"      🔴 {f.get('severity', 'info')}: {f.get('title', 'Unknown')}")
            
            # Phase 3: Learning
            log_info(f"🧠 Phase 3: Learning from findings")
            self._emit_log('info', f"🧠 Phase 3: Learning from findings")
            if findings:
                self.learner.learn(findings)
            
            # Phase 4: Building chains
            log_info(f"🔗 Phase 4: Building attack chains")
            self._emit_log('info', f"🔗 Phase 4: Building attack chains")
            chains = self.brain.analyze_findings(findings)
            if chains:
                log_info(f"   ✅ Built {len(chains)} attack chains")
                self._emit_log('info', f"   ✅ Built {len(chains)} attack chains")
            
            # Phase 5: Generate report
            log_info(f"📄 Phase 5: Generating report")
            self._emit_log('info', f"📄 Phase 5: Generating report")
            
            duration = time.time() - start_time
            
            # Save findings
            for finding in findings:
                finding['target_id'] = target_id
                self.state.save_finding(finding)
            
            # Save chains
            for chain in chains:
                chain['target_id'] = target_id
                self.state.save_chain(chain)
            
            # Update target
            target['status'] = 'completed'
            target['findings'] = findings
            target['chains'] = chains
            target['completed_at'] = get_timestamp()
            self.state.save_target(target)
            
            # Save scan result
            self.scan_results[scan_id] = {
                'target_id': target_id,
                'findings': findings,
                'chains': chains,
                'duration': duration,
                'report_path': None
            }
            
            # Update scan record
            scan_record = self.state.get_scan(scan_id)
            if scan_record:
                scan_record['status'] = 'completed'
                scan_record['end_time'] = get_timestamp()
                scan_record['findings_count'] = len(findings)
                self.state.save_scan(scan_record)
            
            log_info(f"✅ Scan complete! Found {len(findings)} vulnerabilities in {duration:.1f}s")
            self._emit_log('success', f"✅ Scan complete! Found {len(findings)} vulnerabilities")
            if self._socketio:
                try:
                    self._socketio.emit('scan_completed', {
                        'scan_id': scan_id,
                        'target_id': target_id,
                        'findings': len(findings),
                        'duration': duration,
                        'status': 'completed'
                    })
                except:
                    pass
        
        except Exception as e:
            log_error(f"❌ Scan failed: {e}")
            self._emit_log('error', f"❌ Scan failed: {e}")
            if self._socketio:
                try:
                    self._socketio.emit('scan_failed', {
                        'scan_id': scan_id,
                        'target_id': target_id,
                        'error': str(e)
                    })
                except:
                    pass
        
        finally:
            if scan_id in self.running_scans:
                del self.running_scans[scan_id]
    
    def get_scan_result(self, scan_id: str) -> Optional[Dict]:
        """Get the result of a completed scan."""
        return self.scan_results.get(scan_id)
    
    def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan."""
        if scan_id in self.running_scans:
            scan_record = self.state.get_scan(scan_id)
            if scan_record:
                scan_record['status'] = 'stopped'
                scan_record['end_time'] = get_timestamp()
                self.state.save_scan(scan_record)
            
            log_info(f"⏹️ Scan stopped: {scan_id}")
            self._emit_log('warning', f"⏹️ Scan stopped: {scan_id}")
            return True
        return False
    
    # ============================================================
    # Finding Methods
    # ============================================================
    
    def get_findings(self, target_id: Optional[str] = None) -> List[Dict]:
        """Get all findings or findings for a target."""
        if target_id:
            return self.state.get_findings_by_target(target_id)
        return self.state.get_all_findings()
    
    def get_finding(self, finding_id: str) -> Optional[Dict]:
        """Get a specific finding."""
        findings = self.state.get_all_findings()
        for f in findings:
            if f.get('id') == finding_id:
                return f
        return None
    
    # ============================================================
    # Chain Methods
    # ============================================================
    
    def get_chains(self, target_id: Optional[str] = None) -> List[Dict]:
        """Get chains for a target or all chains."""
        if target_id:
            return self.state.get_chains_by_target(target_id)
        return self.state.get_all_chains()
    
    # ============================================================
    # Status
    # ============================================================
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status."""
        stats = self.state.get_statistics()
        
        return {
            'mode': self.config.get('agent.mode', 'hybrid'),
            'targets': len(self.targets),
            'running_scans': len(self.running_scans),
            'total_findings': stats.get('findings', 0),
            'browser_active': False,
            'timestamp': get_timestamp()
        }
    
    # ============================================================
    # State Management
    # ============================================================
    
    def _load_state(self):
        """Load targets from state."""
        targets = self.state.get_all_targets()
        for target in targets:
            self.targets[target['id']] = target
        log_info(f"📂 Loaded {len(self.targets)} targets from state")

    # ============================================================
    # Goal API Methods
    # ============================================================

    def access_system(self) -> Dict[str, Any]:
        """Access the local system like Anydesk/TeamViewer."""
        if not self.system.is_connected:
            self.system.connect()

        tool_status = self.tools.check_all_tools()
        tools_info = {name: {
            'installed': info.installed,
            'path': info.path,
            'version': info.version,
            'enabled': info.enabled
        } for name, info in tool_status.items()}

        return {
            'connected': self.system.is_connected,
            'system_info': self.system.get_system_info(),
            'tools': tools_info,
            'missing_tools': self.tools.get_missing_tools()
        }

    def hunt_bugs(self, target: str, scan_type: str = 'full') -> Dict[str, Any]:
        """Autonomously hunt bugs against a target."""
        target_id = self.add_target(target)
        scan_id = self.scan(target_id, scan_type)

        return {
            'target_id': target_id,
            'scan_id': scan_id,
            'status': 'started' if scan_id else 'failed',
            'scan_type': scan_type
        }

    def learn(self, target_id: Optional[str] = None) -> Dict[str, Any]:
        """Learn from past findings and update the knowledge base."""
        if target_id:
            findings = self.get_findings(target_id)
        else:
            findings = self.get_findings()

        result = self.learner.learn(findings)
        return {
            'target_id': target_id,
            'findings_processed': len(findings),
            'result': result
        }

    def scan_all(self, scan_type: str = 'full') -> Dict[str, Any]:
        """Scan all saved targets for vulnerabilities."""
        scan_ids = []
        for target_id in list(self.targets.keys()):
            scan_id = self.scan(target_id, scan_type)
            if scan_id:
                scan_ids.append(scan_id)

        return {
            'total_targets': len(self.targets),
            'scan_type': scan_type,
            'scan_ids': scan_ids,
            'queued': len(scan_ids)
        }

    def use_tools(self, install_missing: bool = False) -> Dict[str, Any]:
        """Use all configured security tools and optionally install missing ones."""
        tool_status = self.tools.check_all_tools()
        missing = self.tools.get_missing_tools()
        install_results = None

        if install_missing and missing:
            install_results = self.tools.install_all_tools()
            missing = self.tools.get_missing_tools()

        return {
            'tools': {name: {
                'installed': info.installed,
                'path': info.path,
                'version': info.version,
                'enabled': info.enabled
            } for name, info in tool_status.items()},
            'missing_tools': missing,
            'install_results': install_results
        }

    def dashboard(self) -> Dict[str, Any]:
        """Get dashboard availability and configuration."""
        return {
            'enabled': self.config.get('dashboard.enabled', True),
            'host': self.config.get('dashboard.host', '0.0.0.0'),
            'port': self.config.get('dashboard.port', 5000),
            'debug': self.config.get('dashboard.debug', False)
        }

    def save_state(self, state: Dict[str, Any]) -> bool:
        """Save generic agent state for persistence."""
        return self.state.save_state(state)

    def learn_patterns(self, target_id: Optional[str] = None) -> Dict[str, Any]:
        """Learn vulnerability patterns from findings."""
        if target_id:
            findings = self.get_findings(target_id)
        else:
            findings = self.get_findings()

        learn_result = self.learner.learn(findings)
        return {
            'target_id': target_id,
            'patterns_added': learn_result.get('new_patterns', 0),
            'total_patterns': len(self.learner.patterns),
            'result': learn_result
        }

    def tell_limitations(self) -> Dict[str, str]:
        """Explain what the agent cannot do."""
        return self.system.tell_limitations()
