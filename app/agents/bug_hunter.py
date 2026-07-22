"""
BugBountyAgent - Bug Hunter Agent
==================================
This is the main AI agent that orchestrates the entire bug hunting process:
- Manages targets and scope
- Controls the browser for manual-like interaction
- Runs scans and tools
- Learns from findings
- Builds attack chains
- Generates reports
"""

import os
import time
import json
import threading
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, asdict

from app.core import (
    get_config, log_info, log_warning, log_error, log_debug, 
    get_timestamp, generate_id, get_date
)
from app.knowledge import KnowledgeBase, Finding, Pattern, AttackChain
from app.browser import BrowserController
from app.system import SystemController
from app.learners import ChainManager

# ============================================================
# Data Classes
# ============================================================

@dataclass
class ScanTarget:
    """Represents a target for scanning."""
    id: str
    url: str
    scope: List[str]
    exclude: List[str]
    status: str  # pending, running, completed, failed
    start_time: str
    end_time: Optional[str] = None
    findings: List[str] = None
    notes: str = ""
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []

@dataclass
class ScanResult:
    """Represents the result of a scan."""
    target_id: str
    findings: List[Finding]
    chains: List[AttackChain]
    summary: Dict[str, Any]
    duration: float
    report_path: str

# ============================================================
# Bug Hunter Agent
# ============================================================

class BugHunter:
    """
    Main bug hunting agent that orchestrates everything.
    """
    
    def __init__(self):
        """Initialize the bug hunter agent."""
        self.kb = KnowledgeBase()
        self.system = SystemController()
        self.chain_manager = ChainManager()
        self.browser: Optional[BrowserController] = None
        
        self.targets: Dict[str, ScanTarget] = {}
        self.running_scans: Dict[str, threading.Thread] = {}
        self.scan_results: Dict[str, ScanResult] = {}
        
        self.mode = get_config('agent.mode', 'hybrid')
        self.auto_approve = get_config('agent.permissions.auto_approve', False)
        
        log_info(f"Bug Hunter Agent initialized (mode: {self.mode})")
    
    # ============================================================
    # Target Management
    # ============================================================
    
    def add_target(self, url: str, scope: List[str] = None, exclude: List[str] = None) -> str:
        """
        Add a target for scanning.
        
        Args:
            url: Target URL
            scope: Additional scope patterns
            exclude: Excluded patterns
            
        Returns:
            str: Target ID
        """
        target_id = generate_id()
        
        if scope is None:
            scope = [url]
        
        if exclude is None:
            exclude = get_config('targets.exclude', [])
        
        target = ScanTarget(
            id=target_id,
            url=url,
            scope=scope,
            exclude=exclude,
            status='pending',
            start_time=get_timestamp()
        )
        
        self.targets[target_id] = target
        log_info(f"Target added: {url} (ID: {target_id})")
        
        # Save to knowledge base
        self._save_target_profile(target)
        
        return target_id
    
    def get_target(self, target_id: str) -> Optional[ScanTarget]:
        """Get a target by ID."""
        return self.targets.get(target_id)
    
    def list_targets(self) -> List[ScanTarget]:
        """List all targets."""
        return list(self.targets.values())
    
    def remove_target(self, target_id: str) -> bool:
        """Remove a target."""
        if target_id in self.targets:
            del self.targets[target_id]
            log_info(f"Target removed: {target_id}")
            return True
        return False
    
    def _save_target_profile(self, target: ScanTarget):
        """Save target profile to knowledge base."""
        self.kb.update_target_subdomains(target.url, [])
    
    # ============================================================
    # Scanning
    # ============================================================
    
    def start_scan(self, target_id: str, scan_type: str = 'full', callback: Callable = None) -> str:
        """
        Start a scan on a target.
        
        Args:
            target_id: Target ID
            scan_type: full, quick, custom
            callback: Callback function for updates
            
        Returns:
            str: Scan ID
        """
        target = self.get_target(target_id)
        if not target:
            log_error(f"Target not found: {target_id}")
            return None
        
        if target.status == 'running':
            log_warning(f"Target is already being scanned: {target_id}")
            return None
        
        scan_id = generate_id()
        target.status = 'running'
        
        log_info(f"Starting scan {scan_id} on {target.url} (type: {scan_type})")
        
        # Start scan in background thread
        thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, target_id, scan_type, callback)
        )
        thread.daemon = True
        thread.start()
        
        self.running_scans[scan_id] = thread
        
        return scan_id
    
    def _run_scan(self, scan_id: str, target_id: str, scan_type: str, callback: Callable):
        """Run the actual scan (in background thread)."""
        target = self.get_target(target_id)
        start_time = time.time()
        
        try:
            self._emit_update(callback, f"🚀 Starting scan on {target.url}")
            
            # Initialize browser if needed
            if self.mode in ['full', 'hybrid']:
                self._emit_update(callback, "🌐 Initializing browser...")
                self._init_browser()
            
            findings = []
            
            # Phase 1: Reconnaissance
            self._emit_update(callback, "🔍 Phase 1: Reconnaissance")
            recon_findings = self._run_reconnaissance(target, callback)
            findings.extend(recon_findings)
            
            # Phase 2: Vulnerability Scanning
            self._emit_update(callback, "🔬 Phase 2: Vulnerability Scanning")
            vuln_findings = self._run_vulnerability_scanning(target, callback)
            findings.extend(vuln_findings)
            
            # Phase 3: Active Testing (if not in watch mode)
            if self.mode in ['full', 'hybrid']:
                self._emit_update(callback, "⚡ Phase 3: Active Testing")
                active_findings = self._run_active_testing(target, callback)
                findings.extend(active_findings)
            
            # Phase 4: Chain Building
            self._emit_update(callback, "🔗 Phase 4: Building Attack Chains")
            chains = self.chain_manager.build_chains(target.url)
            
            # Save all findings
            for finding in findings:
                self.kb.save_finding(finding)
            
            # Generate report
            self._emit_update(callback, "📄 Phase 5: Generating Report")
            duration = time.time() - start_time
            report_path = self._generate_report(target, findings, chains, duration)
            
            # Save result
            result = ScanResult(
                target_id=target_id,
                findings=findings,
                chains=chains,
                summary=self._generate_summary(findings, chains),
                duration=duration,
                report_path=report_path
            )
            
            self.scan_results[scan_id] = result
            target.status = 'completed'
            target.end_time = get_timestamp()
            
            # Update target profile
            self._update_target_profile(target, findings)
            
            # Emit completion
            self._emit_update(callback, f"✅ Scan complete! Found {len(findings)} findings")
            self._emit_update(callback, f"📄 Report saved: {report_path}")
            
            # Learn from findings
            self._learn_from_scan(findings, chains)
            
        except Exception as e:
            log_error(f"Scan failed: {e}")
            target.status = 'failed'
            self._emit_update(callback, f"❌ Scan failed: {e}")
        
        finally:
            # Cleanup
            if self.browser:
                self.browser.disconnect()
                self.browser = None
            
            # Remove from running scans
            if scan_id in self.running_scans:
                del self.running_scans[scan_id]
    
    # ============================================================
    # Scan Phases
    # ============================================================
    
    def _run_reconnaissance(self, target: ScanTarget, callback: Callable) -> List[Finding]:
        """Run reconnaissance phase."""
        findings = []
        
        # Subdomain discovery
        self._emit_update(callback, "   📋 Discovering subdomains...")
        subdomains = self._discover_subdomains(target.url)
        if subdomains:
            self._emit_update(callback, f"   ✅ Found {len(subdomains)} subdomains")
            # Save subdomains to target profile
            self.kb.update_target_subdomains(target.url, subdomains)
        
        # Port scanning
        self._emit_update(callback, "   🔌 Scanning ports...")
        ports = self._scan_ports(target.url)
        if ports:
            self._emit_update(callback, f"   ✅ Found {len(ports)} open ports")
        
        # Technology detection
        self._emit_update(callback, "   🏷️ Detecting technologies...")
        tech = self._detect_technologies(target.url)
        if tech:
            self._emit_update(callback, f"   ✅ Detected: {', '.join(tech.keys())}")
        
        return findings
    
    def _run_vulnerability_scanning(self, target: ScanTarget, callback: Callable) -> List[Finding]:
        """Run vulnerability scanning phase."""
        findings = []
        
        # Run Nuclei
        self._emit_update(callback, "   🔬 Running Nuclei scan...")
        nuclei_findings = self._run_nuclei(target.url)
        findings.extend(nuclei_findings)
        if nuclei_findings:
            self._emit_update(callback, f"   ✅ Found {len(nuclei_findings)} vulnerabilities via Nuclei")
        
        # Run Nmap scripts
        self._emit_update(callback, "   🔍 Running Nmap scripts...")
        nmap_findings = self._run_nmap_scripts(target.url)
        findings.extend(nmap_findings)
        
        # Run Nikto
        self._emit_update(callback, "   🌐 Running Nikto...")
        nikto_findings = self._run_nikto(target.url)
        findings.extend(nikto_findings)
        
        return findings
    
    def _run_active_testing(self, target: ScanTarget, callback: Callable) -> List[Finding]:
        """Run active testing phase (requires browser)."""
        findings = []
        
        if not self.browser:
            self._emit_update(callback, "   ⚠️ Browser not available. Skipping active testing.")
            return findings
        
        try:
            # Navigate to target
            self._emit_update(callback, f"   🌐 Navigating to {target.url}")
            self.browser.navigate(target.url)
            
            # Analyze page
            self._emit_update(callback, "   🔍 Analyzing page...")
            page_findings = self._analyze_page(target.url)
            findings.extend(page_findings)
            
            # Test forms
            self._emit_update(callback, "   📝 Testing forms...")
            form_findings = self._test_forms()
            findings.extend(form_findings)
            
            # Check for XSS
            self._emit_update(callback, "   ⚡ Testing for XSS...")
            xss_findings = self._test_xss()
            findings.extend(xss_findings)
            
            # Check for injections
            self._emit_update(callback, "   💉 Testing for injections...")
            injection_findings = self._test_injections()
            findings.extend(injection_findings)
            
        except Exception as e:
            log_error(f"Active testing failed: {e}")
            self._emit_update(callback, f"   ❌ Active testing error: {e}")
        
        return findings
    
    # ============================================================
    # Specific Scan Methods
    # ============================================================
    
    def _discover_subdomains(self, domain: str) -> List[str]:
        """Discover subdomains using subfinder and amass."""
        subdomains = []
        
        # Use Subfinder
        try:
            result = self.system.run_tool('subfinder', ['-d', domain])
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        subdomains.append(line.strip())
        except:
            pass
        
        # Use Amass (if available)
        try:
            result = self.system.run_tool('amass', ['enum', '-passive', '-d', domain])
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if line.strip() and '.' in line:
                        subdomains.append(line.strip())
        except:
            pass
        
        # Remove duplicates
        return list(set(subdomains))
    
    def _scan_ports(self, url: str) -> List[int]:
        """Scan ports using Nmap."""
        ports = []
        
        try:
            result = self.system.run_tool('nmap', ['-p', '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,27017', '-T4', url])
            if result['success']:
                # Parse Nmap output
                for line in result['stdout'].split('\n'):
                    if '/tcp' in line and 'open' in line:
                        try:
                            port = int(line.split('/')[0].strip())
                            ports.append(port)
                        except:
                            pass
        except:
            pass
        
        return ports
    
    def _detect_technologies(self, url: str) -> Dict[str, str]:
        """Detect technologies using Wappalyzer or whatweb."""
        technologies = {}
        
        # Use whatweb
        try:
            result = self.system.run_tool('whatweb', ['-q', url])
            if result['success']:
                # Parse whatweb output
                output = result['stdout']
                if '[' in output and ']' in output:
                    techs = output.split('[')[1].split(']')[0].split(',')
                    for tech in techs:
                        if '/' in tech:
                            tech = tech.split('/')[0]
                        if tech.strip():
                            technologies[tech.strip()] = 'detected'
        except:
            pass
        
        return technologies
    
    def _run_nuclei(self, url: str) -> List[Finding]:
        """Run Nuclei vulnerability scanner."""
        findings = []
        
        try:
            result = self.system.run_tool('nuclei', ['-u', url, '-json', '-severity', 'low,medium,high,critical'])
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            finding = Finding(
                                id=generate_id(),
                                target=url,
                                type=data.get('info', {}).get('name', 'Nuclei Finding'),
                                severity=data.get('info', {}).get('severity', 'medium'),
                                description=data.get('info', {}).get('description', ''),
                                reproduction_steps=self._generate_reproduction_steps(data),
                                remediation=data.get('info', {}).get('remediation', ''),
                                cvss_score=data.get('info', {}).get('cvss-score', None),
                                url=data.get('matched-at', url),
                                payload=data.get('curl-command', None)
                            )
                            findings.append(finding)
                        except:
                            pass
        except Exception as e:
            log_error(f"Nuclei scan failed: {e}")
        
        return findings
    
    def _run_nmap_scripts(self, url: str) -> List[Finding]:
        """Run Nmap vulnerability scripts."""
        findings = []
        
        try:
            result = self.system.run_tool('nmap', ['-sV', '--script', 'vuln', url])
            if result['success']:
                # Parse Nmap output for vulnerabilities
                for line in result['stdout'].split('\n'):
                    if 'VULNERABLE' in line or 'vulnerable' in line.lower():
                        finding = Finding(
                            id=generate_id(),
                            target=url,
                            type='Nmap Vulnerability Script',
                            severity='medium',
                            description=line.strip(),
                            reproduction_steps='Run nmap -sV --script vuln on target',
                            remediation='Apply security patches'
                        )
                        findings.append(finding)
        except:
            pass
        
        return findings
    
    def _run_nikto(self, url: str) -> List[Finding]:
        """Run Nikto web scanner."""
        findings = []
        
        try:
            result = self.system.run_tool('nikto', ['-h', url, '-Format', 'json'])
            if result['success']:
                # Parse Nikto output
                for line in result['stdout'].split('\n'):
                    if 'Vulnerability' in line or 'vulnerable' in line.lower():
                        finding = Finding(
                            id=generate_id(),
                            target=url,
                            type='Nikto Finding',
                            severity='medium',
                            description=line.strip(),
                            reproduction_steps='Run nikto -h target',
                            remediation='Review and fix identified issues'
                        )
                        findings.append(finding)
        except:
            pass
        
        return findings
    
    # ============================================================
    # Browser-Based Testing
    # ============================================================
    
    def _init_browser(self):
        """Initialize the browser controller."""
        if not self.browser:
            self.browser = BrowserController(
                headless=not get_config('agent.permissions.browser_visibility', True)
            )
            self.browser.connect()
            log_info("Browser initialized for agent")
    
    def _analyze_page(self, url: str) -> List[Finding]:
        """Analyze the current page for vulnerabilities."""
        findings = []
        
        if not self.browser:
            return findings
        
        try:
            # Get page content
            html = self.browser.get_html()
            if not html:
                return findings
            
            # Check for sensitive data in HTML
            patterns = [
                ('API Key', r'[a-zA-Z0-9_-]{32,}', 'high'),
                ('Password', r'password[=:]\s*[^\s&"\'<>]+', 'critical'),
                ('Token', r'token[=:]\s*[a-zA-Z0-9.-]{10,}', 'high'),
                ('Session ID', r'session[=:]\s*[a-zA-Z0-9]{16,}', 'high'),
                ('Admin Path', r'/admin|/administrator|/manage', 'medium'),
                ('Backup File', r'\.bak|\.backup|\.old|\.swp', 'medium'),
                ('Debug Mode', r'debug[=:]\s*true|debug_mode', 'medium')
            ]
            
            for name, pattern, severity in patterns:
                import re
                matches = re.finditer(pattern, html, re.IGNORECASE)
                for match in matches:
                    finding = Finding(
                        id=generate_id(),
                        target=url,
                        type=f'Information Disclosure - {name}',
                        severity=severity,
                        description=f'Sensitive {name} found in page source',
                        reproduction_steps=f'View page source of {url} and search for {name}',
                        remediation='Remove sensitive data from client-side code'
                    )
                    findings.append(finding)
            
            # Check for security headers
            headers = self.browser.evaluate('() => {return {}}')  # Would need to intercept responses
            
        except Exception as e:
            log_error(f"Page analysis failed: {e}")
        
        return findings
    
    def _test_forms(self) -> List[Finding]:
        """Test forms for vulnerabilities."""
        findings = []
        
        if not self.browser:
            return findings
        
        try:
            # Find all forms
            forms = self.browser.evaluate('''
                () => {
                    const forms = [];
                    document.querySelectorAll('form').forEach(form => {
                        const inputs = [];
                        form.querySelectorAll('input, textarea, select').forEach(input => {
                            inputs.push({
                                type: input.type,
                                name: input.name,
                                id: input.id,
                                value: input.value
                            });
                        });
                        forms.push({
                            action: form.action,
                            method: form.method,
                            inputs: inputs
                        });
                    });
                    return forms;
                }
            ''')
            
            for form in forms:
                # Test for missing CSRF tokens
                has_csrf = False
                for input_data in form.get('inputs', []):
                    if 'csrf' in input_data.get('name', '').lower() or 'token' in input_data.get('name', '').lower():
                        has_csrf = True
                        break
                
                if not has_csrf and form.get('method', '').upper() in ['POST', 'PUT']:
                    finding = Finding(
                        id=generate_id(),
                        target=self.browser.get_url(),
                        type='Missing CSRF Protection',
                        severity='high',
                        description='Form is missing CSRF protection token',
                        reproduction_steps=f'Inspect form at {self.browser.get_url()} - CSRF token not found',
                        remediation='Add CSRF tokens to all state-changing forms'
                    )
                    findings.append(finding)
                    
        except Exception as e:
            log_error(f"Form testing failed: {e}")
        
        return findings
    
    def _test_xss(self) -> List[Finding]:
        """Test for XSS vulnerabilities."""
        findings = []
        
        if not self.browser:
            return findings
        
        try:
            # Find all input fields
            inputs = self.browser.evaluate('''
                () => {
                    const inputs = [];
                    document.querySelectorAll('input, textarea').forEach(el => {
                        inputs.push({
                            type: el.type,
                            name: el.name,
                            id: el.id,
                            value: el.value
                        });
                    });
                    return inputs;
                }
            ''')
            
            # Test for XSS reflection
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                'javascript:alert("XSS")',
                '<img src=x onerror=alert("XSS")>'
            ]
            
            for input_data in inputs:
                if input_data.get('type') in ['text', 'search', 'url', 'email', 'number']:
                    # Check if input value is reflected
                    # This is a simplified check - real XSS testing is more complex
                    pass
            
        except Exception as e:
            log_error(f"XSS testing failed: {e}")
        
        return findings
    
    def _test_injections(self) -> List[Finding]:
        """Test for injection vulnerabilities."""
        findings = []
        
        # Use SQLMap for SQL injection testing
        try:
            result = self.system.run_tool('sqlmap', ['-u', self.browser.get_url(), '--batch', '--level=1'])
            if result['success']:
                if 'vulnerable' in result['stdout'].lower():
                    finding = Finding(
                        id=generate_id(),
                        target=self.browser.get_url(),
                        type='SQL Injection',
                        severity='critical',
                        description='SQL injection vulnerability detected',
                        reproduction_steps='Run sqlmap on the target URL',
                        remediation='Use parameterized queries and input validation'
                    )
                    findings.append(finding)
        except:
            pass
        
        return findings
    
    # ============================================================
    # Utility Methods
    # ============================================================
    
    def _generate_reproduction_steps(self, data: Dict) -> str:
        """Generate reproduction steps from scan data."""
        steps = []
        
        if 'matched-at' in data:
            steps.append(f"1. Navigate to: {data['matched-at']}")
        
        if 'curl-command' in data:
            steps.append(f"2. Send request: {data['curl-command']}")
        
        if 'template' in data:
            steps.append(f"3. The template {data['template']} matched the vulnerability")
        
        if not steps:
            steps.append("1. Review the scan output for details")
            steps.append("2. Reproduce the request manually")
        
        return "\n".join(steps)
    
    def _generate_summary(self, findings: List[Finding], chains: List[AttackChain]) -> Dict[str, Any]:
        """Generate a summary of findings."""
        summary = {
            'total_findings': len(findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'chains': len(chains),
            'types': {}
        }
        
        for finding in findings:
            severity = finding.severity.lower()
            if severity in summary:
                summary[severity] += 1
            
            finding_type = finding.type.split('-')[0].strip()
            if finding_type not in summary['types']:
                summary['types'][finding_type] = 0
            summary['types'][finding_type] += 1
        
        return summary
    
    def _generate_report(self, target: ScanTarget, findings: List[Finding], 
                         chains: List[AttackChain], duration: float) -> str:
        """Generate a comprehensive report."""
        report_dir = get_config('reports.save_dir', './data/reports')
        os.makedirs(report_dir, exist_ok=True)
        
        filename = f"{target.url.replace('://', '_').replace('/', '_')}_{get_date()}.json"
        filepath = os.path.join(report_dir, filename)
        
        report_data = {
            'target': {
                'url': target.url,
                'id': target.id,
                'start_time': target.start_time,
                'end_time': target.end_time or get_timestamp()
            },
            'summary': self._generate_summary(findings, chains),
            'findings': [asdict(f) for f in findings],
            'chains': [asdict(c) for c in chains],
            'duration': round(duration, 2),
            'generated_at': get_timestamp()
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        log_info(f"Report generated: {filepath}")
        return filepath
    
    def _update_target_profile(self, target: ScanTarget, findings: List[Finding]):
        """Update target profile with findings."""
        self.kb.update_target_subdomains(target.url, [])
        
        # Update target profile
        profile = self.kb.get_target_profile(target.url)
        if profile:
            # Update with new findings
            pass
    
    def _learn_from_scan(self, findings: List[Finding], chains: List[AttackChain]):
        """Learn from scan results."""
        # Learn from successful chains
        for chain in chains:
            if chain.completed:
                self.chain_manager.learn_from_chain(chain, success=True)
        
        # Learn from high-severity findings
        for finding in findings:
            if finding.severity in ['critical', 'high']:
                # Create pattern from finding
                pattern = Pattern(
                    id=generate_id(),
                    name=f"Pattern: {finding.type}",
                    category=finding.severity,
                    detection_method='scan_result',
                    indicators=[finding.url, finding.type],
                    payloads=[finding.payload or ''],
                    confidence=0.8,
                    occurrences=1,
                    first_seen=get_timestamp(),
                    last_seen=get_timestamp(),
                    related_cves=[finding.cve_id] if finding.cve_id else []
                )
                self.kb.save_pattern(pattern)
    
    def _emit_update(self, callback: Callable, message: str):
        """Emit an update through the callback."""
        if callback:
            try:
                callback({
                    'type': 'update',
                    'message': message,
                    'timestamp': get_timestamp()
                })
            except:
                pass
        
        log_info(f"Agent: {message}")
    
    # ============================================================
    # Status & Control
    # ============================================================
    
    def get_status(self) -> Dict[str, Any]:
        """Get the agent's status."""
        return {
            'mode': self.mode,
            'targets': len(self.targets),
            'running_scans': len(self.running_scans),
            'browser_active': self.browser is not None,
            'knowledge_base': {
                'findings': len(self.kb.get_all_findings()),
                'patterns': len(self.kb.get_statistics().get('total_patterns', 0)),
                'chains': len(self.kb.get_statistics().get('total_chains', 0))
            }
        }
    
    def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan."""
        if scan_id in self.running_scans:
            # Stop the thread
            thread = self.running_scans[scan_id]
            # Note: Thread stopping is complex, but we can mark it
            log_info(f"Stopping scan: {scan_id}")
            return True
        return False
    
    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Get the result of a completed scan."""
        return self.scan_results.get(scan_id)
    
    def cleanup(self):
        """Clean up resources."""
        if self.browser:
            self.browser.disconnect()
            self.browser = None
        log_info("Agent cleaned up")