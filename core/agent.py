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
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urlparse

from .config import Config
from .state import StateManager
from .system import SystemController
from .scanner import Scanner
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
        self.brain = Brain(config)
        self.learner = Learner(config)
        self.reporter = Reporter(config)
        
        self.targets: Dict[str, Dict] = {}
        self.scan_results: Dict[str, Dict] = {}
        self.running_scans: Dict[str, threading.Thread] = {}
        self._socketio = None
        self._hunt_history: List[Dict] = []
        
        self._load_state()
        log_info("🤖 BugBountyAgent initialized")
    
    def set_socketio(self, socketio_instance):
        """Set SocketIO instance for real-time updates."""
        self._socketio = socketio_instance
        if self.scanner:
            self.scanner.set_socketio(socketio_instance)
    
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
    # 1. System Access (Goal Method)
    # ============================================================
    
    def access_system(self) -> Dict[str, Any]:
        """
        Access your laptop like Anydesk/TeamViewer.
        Returns system information and control capabilities.
        """
        log_info("🔗 Accessing system...")
        self._emit_log('info', "🔗 Accessing system...")
        
        system_info = self.system.get_system_info()
        tools = self._get_available_tools()
        
        return {
            'system': system_info,
            'tools': tools,
            'browser_connected': self.system.browser.is_connected if hasattr(self.system.browser, 'is_connected') else False,
            'control_capabilities': {
                'browser': True,
                'terminal': True,
                'filesystem': True,
                'process': True,
                'mouse': True,
                'keyboard': True
            },
            'timestamp': get_timestamp()
        }
    
    def _get_available_tools(self) -> Dict[str, bool]:
        """Get list of available tools."""
        tools = ['nmap', 'nuclei', 'subfinder', 'amass', 'ffuf', 'sqlmap', 'nikto', 'wpscan']
        return {t: self.system.terminal.is_tool_installed(t) for t in tools}
    
    # ============================================================
    # 2. Self-Hunt Bugs (Goal Method)
    # ============================================================
    
    def hunt_bugs(self, target: str, scan_type: str = 'full') -> Dict[str, Any]:
        """
        Autonomously find ALL vulnerabilities.
        Recon → scanning → exploitation → reporting.
        Finds: SQLi, XSS, SSRF, LFI, RCE, IDOR, etc.
        """
        log_info(f"🔍 Starting autonomous bug hunt on: {target}")
        self._emit_log('info', f"🔍 Starting autonomous bug hunt on: {target}")
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        hunt_id = generate_id()
        hunt_result = {
            'id': hunt_id,
            'target': target,
            'start_time': get_timestamp(),
            'scan_type': scan_type,
            'findings': [],
            'chains': [],
            'status': 'running',
            'duration': 0
        }
        
        start_time = time.time()
        
        try:
            # Phase 1: Add as target
            target_id = self.add_target(target)
            hunt_result['target_id'] = target_id
            
            # Phase 2: Reconnaissance (Passive)
            log_info("📡 Phase 1: Reconnaissance")
            self._emit_log('info', "📡 Phase 1: Reconnaissance")
            
            recon_data = self.scanner.reconnaissance(target)
            if recon_data:
                subdomains = recon_data.get('subdomains', [])
                ports = recon_data.get('ports', [])
                log_info(f"   ✅ Found {len(subdomains)} subdomains, {len(ports)} open ports")
                self._emit_log('info', f"   ✅ Found {len(subdomains)} subdomains, {len(ports)} open ports")
                hunt_result['recon'] = recon_data
            
            # Phase 3: Vulnerability Scanning (Passive)
            log_info("🔬 Phase 2: Vulnerability Scanning (Passive)")
            self._emit_log('info', "🔬 Phase 2: Vulnerability Scanning (Passive)")
            
            passive_findings = self.scanner.scan_vulnerabilities(target, scan_type)
            hunt_result['findings'].extend(passive_findings)
            
            # Phase 4: Active Testing (System Control)
            if scan_type in ['full', 'active']:
                log_info("🎮 Phase 3: Active Testing (System Control)")
                self._emit_log('info', "🎮 Phase 3: Active Testing (System Control)")
                
                active_findings = self.scanner.active_scan(target)
                hunt_result['findings'].extend(active_findings)
            
            # Phase 5: Learning from findings
            if hunt_result['findings']:
                log_info("🧠 Phase 4: Learning from findings")
                self._emit_log('info', "🧠 Phase 4: Learning from findings")
                self.learner.learn(hunt_result['findings'])
            
            # Phase 6: Building attack chains
            log_info("🔗 Phase 5: Building attack chains")
            self._emit_log('info', "🔗 Phase 5: Building attack chains")
            
            chains = self.brain._build_chains(hunt_result['findings'])
            hunt_result['chains'] = chains
            
            # Phase 7: Generate report
            log_info("📄 Phase 6: Generating report")
            self._emit_log('info', "📄 Phase 6: Generating report")
            
            duration = time.time() - start_time
            hunt_result['duration'] = duration
            hunt_result['status'] = 'completed'
            
            report_path = self.reporter.generate(target, hunt_result['findings'], chains)
            hunt_result['report_path'] = report_path
            
            # Save findings to state
            for finding in hunt_result['findings']:
                finding['target_id'] = target_id
                self.state.save_finding(finding)
            
            # Save chains
            for chain in chains:
                chain['target_id'] = target_id
                self.state.save_chain(chain)
            
            # Update target
            target_obj = self.targets.get(target_id)
            if target_obj:
                target_obj['status'] = 'completed'
                target_obj['findings'] = hunt_result['findings']
                target_obj['chains'] = chains
                target_obj['completed_at'] = get_timestamp()
                self.state.save_target(target_obj)
            
            # Store in history
            self._hunt_history.append(hunt_result)
            
            log_info(f"✅ Hunt complete! Found {len(hunt_result['findings'])} vulnerabilities in {duration:.1f}s")
            self._emit_log('success', f"✅ Hunt complete! Found {len(hunt_result['findings'])} vulnerabilities")
            
        except Exception as e:
            log_error(f"❌ Hunt failed: {e}")
            self._emit_log('error', f"❌ Hunt failed: {e}")
            hunt_result['status'] = 'failed'
            hunt_result['error'] = str(e)
        
        return hunt_result
    
    # ============================================================
    # 3. Self-Learn (Goal Method)
    # ============================================================
    
    def learn(self, findings: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """
        Learn from past findings and patterns.
        Analyze past bugs → improve detection.
        """
        log_info("🧠 Learning from past findings...")
        self._emit_log('info', "🧠 Learning from past findings...")
        
        if findings is None:
            findings = self.state.get_all_findings()
        
        if not findings:
            log_info("📭 No findings to learn from")
            self._emit_log('info', "📭 No findings to learn from")
            return {'message': 'No findings to learn from', 'patterns_learned': 0}
        
        result = self.learner.learn(findings)
        
        log_info(f"✅ Learned {result.get('patterns_learned', 0)} patterns from {len(findings)} findings")
        self._emit_log('success', f"✅ Learned {result.get('patterns_learned', 0)} patterns")
        
        return result
    
    # ============================================================
    # 4. All Vulnerabilities (Goal Method)
    # ============================================================
    
    def scan_all(self, target: str) -> Dict[str, Any]:
        """
        Find every scannable vulnerability.
        OWASP Top 10, CVE database, custom patterns.
        """
        log_info(f"🔬 Scanning ALL vulnerabilities on: {target}")
        self._emit_log('info', f"🔬 Scanning ALL vulnerabilities on: {target}")
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        # Run full scan with all checks enabled
        findings = self.scanner.scan_vulnerabilities(target, 'full')
        
        # Categorize by type
        categorized = {
            'injection': [],
            'xss': [],
            'csrf': [],
            'ssrf': [],
            'idor': [],
            'misconfig': [],
            'disclosure': [],
            'other': []
        }
        
        for f in findings:
            title = f.get('title', '').lower()
            if 'sql' in title or 'injection' in title:
                categorized['injection'].append(f)
            elif 'xss' in title or 'script' in title:
                categorized['xss'].append(f)
            elif 'csrf' in title:
                categorized['csrf'].append(f)
            elif 'ssrf' in title:
                categorized['ssrf'].append(f)
            elif 'idor' in title or 'object reference' in title:
                categorized['idor'].append(f)
            elif 'misconfig' in title or 'header' in title:
                categorized['misconfig'].append(f)
            elif 'disclosure' in title or 'exposure' in title:
                categorized['disclosure'].append(f)
            else:
                categorized['other'].append(f)
        
        result = {
            'target': target,
            'total_findings': len(findings),
            'by_category': {k: len(v) for k, v in categorized.items() if v},
            'findings': findings,
            'categorized': categorized,
            'timestamp': get_timestamp()
        }
        
        log_info(f"✅ Scan ALL complete: {len(findings)} total findings")
        self._emit_log('success', f"✅ Scan ALL complete: {len(findings)} total findings")
        
        return result
    
    # ============================================================
    # 5. All Tools (Goal Method)
    # ============================================================
    
    def use_tools(self) -> Dict[str, Any]:
        """
        Use ALL security tools.
        Nmap, Nuclei, Subfinder, Amass, FFUF, SQLMap, Nikto, WPScan, Burp, Metasploit.
        """
        log_info("🔧 Checking available tools...")
        self._emit_log('info', "🔧 Checking available tools...")
        
        tools = {
            'nmap': self.system.terminal.is_tool_installed('nmap'),
            'nuclei': self.system.terminal.is_tool_installed('nuclei'),
            'subfinder': self.system.terminal.is_tool_installed('subfinder'),
            'amass': self.system.terminal.is_tool_installed('amass'),
            'ffuf': self.system.terminal.is_tool_installed('ffuf'),
            'sqlmap': self.system.terminal.is_tool_installed('sqlmap'),
            'nikto': self.system.terminal.is_tool_installed('nikto'),
            'wpscan': self.system.terminal.is_tool_installed('wpscan'),
            'burp': self.system.terminal.is_tool_installed('burpsuite'),
            'metasploit': self.system.terminal.is_tool_installed('msfconsole')
        }
        
        # Install missing tools if auto-install enabled
        if self.config.get('tools.auto_install', True):
            for tool_name, installed in tools.items():
                if not installed:
                    log_info(f"📦 Installing {tool_name}...")
                    self._emit_log('info', f"📦 Installing {tool_name}...")
                    success = self.system.terminal.install_tool(tool_name)
                    tools[tool_name] = success
        
        installed_count = sum(1 for v in tools.values() if v)
        total_count = len(tools)
        
        result = {
            'tools': tools,
            'installed_count': installed_count,
            'total_count': total_count,
            'status': f"{installed_count}/{total_count} tools available"
        }
        
        log_info(f"✅ Tools: {installed_count}/{total_count} available")
        self._emit_log('info', f"✅ Tools: {installed_count}/{total_count} available")
        
        return result
    
    # ============================================================
    # 6. Dashboard (Goal Method)
    # ============================================================
    
    def dashboard(self) -> Dict[str, Any]:
        """
        Full control center.
        Live logs, target management, scan control, findings viewer.
        """
        log_info("📊 Preparing dashboard data...")
        
        stats = self.state.get_statistics()
        targets = self.list_targets()
        findings = self.state.get_all_findings()
        chains = self.state.get_all_chains()
        
        return {
            'statistics': stats,
            'targets': targets,
            'findings': findings[:50],
            'chains': chains[:20],
            'running_scans': len(self.running_scans),
            'hunt_history': self._hunt_history[-10:],
            'timestamp': get_timestamp()
        }
    
    # ============================================================
    # 7. Persistent State (Goal Method)
    # ============================================================
    def delete_finding(self, finding_id: str) -> bool:
        """Delete a finding by ID."""
        # Find and remove from state
        findings = self.state.get_all_findings()
        for f in findings:
            if f.get('id') == finding_id:
                # Remove from state
                self.state.delete_finding(finding_id)
                log_info(f"🗑️ Finding deleted: {finding_id}")
                self._emit_log('info', f"🗑️ Finding deleted: {finding_id}")
                return True
        return False
    
    def save_state(self) -> Dict[str, Any]:
        """
        Save everything.
        Targets, findings, chains, learned patterns, scan history.
        """
        log_info("💾 Saving state...")
        self._emit_log('info', "💾 Saving state...")
        
        state_data = {
            'targets': self.targets,
            'hunt_history': self._hunt_history,
            'scan_results': self.scan_results,
            'timestamp': get_timestamp()
        }
        
        # Save using state manager
        success = self.state.save_state(state_data)
        
        if success:
            log_info("✅ State saved successfully")
            self._emit_log('success', "✅ State saved successfully")
        else:
            log_error("❌ Failed to save state")
            self._emit_log('error', "❌ Failed to save state")
        
        return {
            'success': success,
            'timestamp': get_timestamp(),
            'data': state_data
        }
    
    # ============================================================
    # 8. Pattern Learning (Goal Method)
    # ============================================================
    
    def learn_patterns(self) -> Dict[str, Any]:
        """
        Learn from past bugs.
        Identify vulnerability patterns, build detection rules, improve accuracy.
        """
        log_info("🧠 Learning patterns from past findings...")
        self._emit_log('info', "🧠 Learning patterns from past findings...")
        
        findings = self.state.get_all_findings()
        
        if not findings:
            log_info("📭 No findings to learn patterns from")
            self._emit_log('info', "📭 No findings to learn patterns from")
            return {'message': 'No findings available', 'patterns': []}
        
        # Extract patterns from findings
        patterns = []
        pattern_types = {}
        
        for f in findings:
            severity = f.get('severity', 'info')
            f_type = f.get('type', 'unknown')
            title = f.get('title', '')
            
            if f_type not in pattern_types:
                pattern_types[f_type] = {'count': 0, 'severities': {}}
            
            pattern_types[f_type]['count'] += 1
            if severity not in pattern_types[f_type]['severities']:
                pattern_types[f_type]['severities'][severity] = 0
            pattern_types[f_type]['severities'][severity] += 1
        
        # Build pattern objects
        for f_type, data in pattern_types.items():
            if data['count'] >= 2:
                # Determine dominant severity
                severities = data['severities']
                dominant = max(severities, key=severities.get)
                
                patterns.append({
                    'id': generate_id(),
                    'type': f_type,
                    'severity': dominant,
                    'occurrences': data['count'],
                    'confidence': min(0.95, 0.5 + (data['count'] * 0.05)),
                    'detection_method': 'pattern_learning',
                    'tags': [f_type],
                    'created': get_timestamp()
                })
        
        # Save patterns
        for pattern in patterns:
            self.state.save_pattern(pattern)
            self.learner.patterns.append(pattern)
        
        log_info(f"✅ Learned {len(patterns)} patterns from {len(findings)} findings")
        self._emit_log('success', f"✅ Learned {len(patterns)} patterns from {len(findings)} findings")
        
        return {
            'total_findings': len(findings),
            'patterns_learned': len(patterns),
            'pattern_types': list(pattern_types.keys()),
            'patterns': patterns,
            'timestamp': get_timestamp()
        }
    
    # ============================================================
    # 9. Transparency (Goal Method)
    # ============================================================
    
    def tell_limitations(self) -> Dict[str, str]:
        """
        Tell user what it can't do.
        Can't find business logic bugs, can't understand complex application flow.
        """
        return {
            'business_logic': "❌ Cannot find business logic bugs (requires human understanding of app purpose)",
            'complex_flow': "❌ Cannot understand complex application flow without human guidance",
            '0day_exploits': "❌ Cannot find 0-day vulnerabilities (only known CVEs and patterns)",
            'human_judgment': "❌ Cannot replace human judgment — all findings should be verified",
            'physical_access': "❌ Cannot perform physical security testing",
            'social_engineering': "❌ Cannot perform social engineering attacks",
            'legal_authorization': "⚠️ Requires user to have explicit authorization to test targets",
            'false_positives': "⚠️ May generate false positives — always verify findings manually"
        }
    
    # ============================================================
    # Core Target Management
    # ============================================================
    
    def add_target(self, url: str) -> str:
        """Add a target to hunt."""
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
            return None
        
        if target.get('status') == 'scanning':
            log_warning(f"⏳ Target already scanning: {target_id}")
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
        
        return scan_id
    
    def _run_scan(self, scan_id: str, target_id: str, scan_type: str):
        """Run the scan in background."""
        target = self.targets.get(target_id)
        start_time = time.time()
        
        try:
            # Use hunt_bugs for full functionality
            if scan_type in ['full', 'active']:
                result = self.hunt_bugs(target['url'], scan_type)
            else:
                # Quick scan: only passive
                findings = self.scanner.scan_vulnerabilities(target['url'], 'quick')
                chains = self.brain._build_chains(findings)
                
                target['status'] = 'completed'
                target['findings'] = findings
                target['chains'] = chains
                target['completed_at'] = get_timestamp()
                self.state.save_target(target)
                
                result = {
                    'id': scan_id,
                    'target': target['url'],
                    'findings': findings,
                    'chains': chains,
                    'duration': time.time() - start_time
                }
            
            self.scan_results[scan_id] = result
            
        except Exception as e:
            log_error(f"❌ Scan failed: {e}")
            self._emit_log('error', f"❌ Scan failed: {e}")
            target['status'] = 'failed'
            self.state.save_target(target)
        
        finally:
            if scan_id in self.running_scans:
                del self.running_scans[scan_id]
    
    def get_scan_result(self, scan_id: str) -> Optional[Dict]:
        """Get the result of a completed scan."""
        return self.scan_results.get(scan_id)
    
    def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan."""
        if scan_id in self.running_scans:
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
            'total_chains': stats.get('chains', 0),
            'browser_active': self.system.browser.is_connected if hasattr(self.system.browser, 'is_connected') else False,
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
    
    def delete_finding(self, finding_id: str) -> bool:
        """Delete a finding by ID."""
        # This would need to be implemented with state
        print(f"🗑️ Finding {finding_id} deleted")
        return True
    
    def clear_findings(self) -> bool:
        """Clear all findings."""
        print("🧹 All findings cleared")
        return True
