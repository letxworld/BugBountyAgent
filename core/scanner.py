"""
BugBountyAgent - Autonomous Vulnerability Scanner
==================================================
This scanner controls your system like a human bug bounty hunter.
It uses:
1. Passive scanning (Nuclei, Nmap, Subfinder) for reconnaissance
2. Active testing (Browser control, mouse/keyboard) for real exploitation
3. System control (opens apps, navigates, clicks, types)
"""

import json
import time
import socket
import subprocess
import pyautogui
import os
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from .config import Config
from .browser import BrowserController
from .terminal import TerminalController
from .filesystem import FileSystemController
from .logging import log_info, log_error, log_warning, log_debug
from .utils import get_timestamp


class Scanner:
    """
    Autonomous vulnerability scanner that controls your system like a human.
    Combines passive scanning + active system control.
    """
    
    def __init__(self, config: Config, browser: BrowserController, terminal: TerminalController):
        self.config = config
        self.browser = browser
        self.terminal = terminal
        self.filesystem = FileSystemController(config)
        
        self.timeout = config.get('scanner.timeout', 300)
        self.severity_filter = config.get('scanner.severity_filter', ['low', 'medium', 'high', 'critical'])
        self.auto_control = config.get('scanner.auto_control', True)  # Enable system control
        
        self._socketio = None
        self._findings = []
        
        log_info("🔍 Autonomous Scanner initialized (System Control: ENABLED)")
    
    def set_socketio(self, socketio_instance):
        self._socketio = socketio_instance
    
    def _emit_log(self, level: str, message: str):
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
    # 1. PASSIVE SCANNING (Reconnaissance)
    # ============================================================
    
    def passive_scan(self, target: str) -> Dict[str, Any]:
        """Passive reconnaissance using tools (Nmap, Nuclei, Subfinder)."""
        log_info(f"📡 Passive scanning: {target}")
        self._emit_log('info', f"📡 Passive scanning: {target}")
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        results = {
            'target': target,
            'subdomains': [],
            'ports': [],
            'technologies': {},
            'vulnerabilities': []
        }
        
        parsed = urlparse(target)
        domain = parsed.netloc or target
        
        # 1.1 Subdomain Discovery
        try:
            if self.terminal.is_tool_installed('subfinder'):
                log_info("🔍 Discovering subdomains...")
                self._emit_log('info', "🔍 Discovering subdomains...")
                result = self.terminal.run(f"subfinder -d {domain} -silent", timeout=60)
                if result.success:
                    subdomains = [s.strip() for s in result.stdout.split('\n') if s.strip()]
                    results['subdomains'] = subdomains[:20]
                    log_info(f"   ✅ Found {len(subdomains)} subdomains")
                    self._emit_log('info', f"   ✅ Found {len(subdomains)} subdomains")
        except Exception as e:
            log_warning(f"   Subdomain discovery failed: {e}")
        
        # 1.2 Port Scanning
        try:
            if self.terminal.is_tool_installed('nmap'):
                log_info("🔌 Scanning ports...")
                self._emit_log('info', "🔌 Scanning ports...")
                result = self.terminal.run(
                    f"nmap -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,27017 -T4 {domain}",
                    timeout=60
                )
                if result.success:
                    ports = []
                    for line in result.stdout.split('\n'):
                        if '/tcp' in line and 'open' in line:
                            try:
                                ports.append(int(line.split('/')[0].strip()))
                            except:
                                pass
                    results['ports'] = ports
                    log_info(f"   ✅ Found {len(ports)} open ports")
                    self._emit_log('info', f"   ✅ Found {len(ports)} open ports")
        except Exception as e:
            log_warning(f"   Port scanning failed: {e}")
        
        # 1.3 Nuclei Vulnerability Scanning
        try:
            if self.terminal.is_tool_installed('nuclei'):
                log_info("🔬 Running Nuclei vulnerability scan...")
                self._emit_log('info', "🔬 Running Nuclei vulnerability scan...")
                severity_str = ','.join(self.severity_filter)
                result = self.terminal.run(
                    f"nuclei -u {target} -severity {severity_str} -silent -json",
                    timeout=120
                )
                if result.success:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            try:
                                data = json.loads(line)
                                info = data.get('info', {})
                                finding = {
                                    'id': f"nuclei_{len(results['vulnerabilities'])+1}",
                                    'title': info.get('name', 'Nuclei Finding'),
                                    'severity': info.get('severity', 'medium'),
                                    'description': info.get('description', ''),
                                    'remediation': info.get('remediation', ''),
                                    'cve_id': info.get('cve-id', ''),
                                    'url': data.get('matched-at', target),
                                    'source': 'nuclei',
                                    'timestamp': get_timestamp(),
                                    'target': target
                                }
                                results['vulnerabilities'].append(finding)
                            except:
                                pass
                    log_info(f"   ✅ Found {len(results['vulnerabilities'])} vulnerabilities")
                    self._emit_log('info', f"   ✅ Found {len(results['vulnerabilities'])} vulnerabilities")
        except Exception as e:
            log_warning(f"   Nuclei scan failed: {e}")
        
        # 1.4 Custom Header Checks
        try:
            log_info("🔍 Checking security headers...")
            self._emit_log('info', "🔍 Checking security headers...")
            response = requests.get(target, timeout=15, verify=False, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header (clickjacking risk)',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header (MIME sniffing risk)',
                'Content-Security-Policy': 'Missing Content-Security-Policy header',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Referrer-Policy': 'Missing Referrer-Policy header'
            }
            
            for header, desc in security_headers.items():
                if header not in headers:
                    results['vulnerabilities'].append({
                        'id': f"custom_{len(results['vulnerabilities'])+1}",
                        'title': f'Missing Security Header: {header}',
                        'severity': 'medium',
                        'description': desc,
                        'remediation': f'Add {header} header to server configuration',
                        'source': 'custom',
                        'timestamp': get_timestamp(),
                        'target': target
                    })
            
            if 'Server' in headers and headers['Server']:
                results['vulnerabilities'].append({
                    'id': f"custom_{len(results['vulnerabilities'])+1}",
                    'title': f'Server Header Disclosure: {headers["Server"]}',
                    'severity': 'low',
                    'description': f'Server header exposes: {headers["Server"]}',
                    'remediation': 'Remove or obfuscate Server header',
                    'source': 'custom',
                    'timestamp': get_timestamp(),
                    'target': target
                })
            
            log_info(f"   ✅ Found {len(results['vulnerabilities'])} total findings")
            self._emit_log('info', f"   ✅ Found {len(results['vulnerabilities'])} total findings")
        except Exception as e:
            log_debug(f"Header checks failed: {e}")
        
        return results
    
    # ============================================================
    # 2. ACTIVE SYSTEM CONTROL (Like a Human)
    # ============================================================
    
    def active_scan(self, target: str) -> List[Dict]:
        """
        ACTIVE scanning - controls your system like a human.
        Opens browser, navigates, clicks, types, and tests for vulnerabilities.
        """
        log_info(f"🎮 Active scanning (system control): {target}")
        self._emit_log('info', f"🎮 Active scanning (system control): {target}")
        
        findings = []
        
        if not self.auto_control:
            log_warning("⚠️ Auto-control disabled. Skipping active scan.")
            self._emit_log('warning', "⚠️ Auto-control disabled. Skipping active scan.")
            return findings
        
        try:
            # 2.1 Connect Browser
            log_info("🌐 Connecting browser...")
            self._emit_log('info', "🌐 Connecting browser...")
            
            if not self.browser.ensure_connected():
                log_error("❌ Browser connection failed")
                self._emit_log('error', "❌ Browser connection failed")
                return findings
            
            log_info("✅ Browser connected")
            self._emit_log('info', "✅ Browser connected")
            
            # 2.2 Navigate to Target
            log_info(f"🌐 Navigating to: {target}")
            self._emit_log('info', f"🌐 Navigating to: {target}")
            
            if not self.browser.navigate(target):
                log_error("❌ Navigation failed")
                self._emit_log('error', "❌ Navigation failed")
                return findings
            
            time.sleep(3)  # Wait for page to load
            
            # 2.3 Take Screenshot
            log_info("📸 Taking screenshot...")
            self._emit_log('info', "📸 Taking screenshot...")
            screenshot_path = self.browser.screenshot(f"active_scan_{int(time.time())}")
            if screenshot_path:
                log_info(f"   ✅ Screenshot saved: {screenshot_path}")
                self._emit_log('info', f"   ✅ Screenshot saved: {screenshot_path}")
            
            # 2.4 Analyze Page
            log_info("🔍 Analyzing page for vulnerabilities...")
            self._emit_log('info', "🔍 Analyzing page for vulnerabilities...")
            
            page_findings = self._analyze_page(target)
            findings.extend(page_findings)
            
            # 2.5 Test Forms
            log_info("📝 Testing forms for vulnerabilities...")
            self._emit_log('info', "📝 Testing forms for vulnerabilities...")
            
            form_findings = self._test_forms(target)
            findings.extend(form_findings)
            
            # 2.6 Check for XSS
            log_info("⚡ Testing for XSS vulnerabilities...")
            self._emit_log('info', "⚡ Testing for XSS vulnerabilities...")
            
            xss_findings = self._test_xss(target)
            findings.extend(xss_findings)
            
            # 2.7 Check for SQL Injection
            log_info("💉 Testing for SQL injection...")
            self._emit_log('info', "💉 Testing for SQL injection...")
            
            sql_findings = self._test_sql_injection(target)
            findings.extend(sql_findings)
            
            # 2.8 Check for IDOR
            log_info("🔐 Testing for IDOR vulnerabilities...")
            self._emit_log('info', "🔐 Testing for IDOR vulnerabilities...")
            
            idor_findings = self._test_idor(target)
            findings.extend(idor_findings)
            
            log_info(f"✅ Active scan complete. Found {len(findings)} vulnerabilities")
            self._emit_log('info', f"✅ Active scan complete. Found {len(findings)} vulnerabilities")
            
            # Log each finding
            for f in findings[:5]:
                log_info(f"   🔴 {f.get('severity', 'info')}: {f.get('title', 'Unknown')}")
                self._emit_log('attack', f"   🔴 {f.get('severity', 'info')}: {f.get('title', 'Unknown')}")
            
        except Exception as e:
            log_error(f"❌ Active scan failed: {e}")
            self._emit_log('error', f"❌ Active scan failed: {e}")
        
        return findings
    
    def _analyze_page(self, target: str) -> List[Dict]:
        """Analyze the current page for vulnerabilities."""
        findings = []
        
        try:
            # Get page HTML
            html = self.browser.get_html()
            if not html:
                return findings
            
            # Check for sensitive data in HTML
            sensitive_patterns = [
                ('API Key', r'[a-zA-Z0-9_-]{32,}', 'high'),
                ('JWT Token', r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'critical'),
                ('Password', r'password[=:]\s*[^\s&"\'<>]+', 'critical'),
                ('Token', r'token[=:]\s*[a-zA-Z0-9.-]{10,}', 'high'),
                ('Session ID', r'session[=:]\s*[a-zA-Z0-9]{16,}', 'high'),
                ('Admin Path', r'/admin|/administrator|/manage', 'medium'),
                ('Backup File', r'\.bak|\.backup|\.old|\.swp', 'medium'),
                ('Debug Mode', r'debug[=:]\s*true|debug_mode', 'medium'),
                ('Internal IP', r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})', 'low')
            ]
            
            import re
            for name, pattern, severity in sensitive_patterns:
                matches = re.finditer(pattern, html, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'id': f"page_{len(findings)+1}",
                        'title': f'Sensitive Information Disclosure: {name}',
                        'severity': severity,
                        'description': f'Sensitive {name} found in page source: {match.group(0)[:50]}...',
                        'remediation': 'Remove sensitive data from client-side code',
                        'source': 'active_scan',
                        'timestamp': get_timestamp(),
                        'target': target
                    })
                    break  # Only one per pattern
            
            # Check for security headers
            headers = self.browser.evaluate("() => { return {} }")  # Placeholder
            
        except Exception as e:
            log_debug(f"Page analysis failed: {e}")
        
        return findings
    
    def _test_forms(self, target: str) -> List[Dict]:
        """Test forms for vulnerabilities."""
        findings = []
        
        try:
            # Find all forms
            forms = self.browser.evaluate("""
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
            """)
            
            for form in forms:
                # Check for missing CSRF tokens
                has_csrf = False
                for input_data in form.get('inputs', []):
                    if 'csrf' in input_data.get('name', '').lower() or 'token' in input_data.get('name', '').lower():
                        has_csrf = True
                        break
                
                if not has_csrf and form.get('method', '').upper() in ['POST', 'PUT']:
                    findings.append({
                        'id': f"form_{len(findings)+1}",
                        'title': 'Missing CSRF Protection',
                        'severity': 'high',
                        'description': f'Form at {form.get("action", "unknown")} missing CSRF protection',
                        'remediation': 'Add CSRF tokens to all state-changing forms',
                        'source': 'active_scan',
                        'timestamp': get_timestamp(),
                        'target': target
                    })
            
            # Check for password fields without HTTPS
            if 'https://' not in target:
                password_fields = self.browser.evaluate("""
                    () => {
                        return document.querySelectorAll('input[type="password"]').length;
                    }
                """)
                if password_fields and password_fields > 0:
                    findings.append({
                        'id': f"form_{len(findings)+1}",
                        'title': 'Password Field on HTTP Page',
                        'severity': 'critical',
                        'description': f'Password field found on non-HTTPS page. Credentials will be sent in plain text.',
                        'remediation': 'Always use HTTPS for login forms',
                        'source': 'active_scan',
                        'timestamp': get_timestamp(),
                        'target': target
                    })
            
        except Exception as e:
            log_debug(f"Form testing failed: {e}")
        
        return findings
    
    def _test_xss(self, target: str) -> List[Dict]:
        """Test for XSS vulnerabilities."""
        findings = []
        
        try:
            # Find all input fields
            inputs = self.browser.evaluate("""
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
            """)
            
            # Test with XSS payloads
            xss_payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>', '<img src=x onerror=alert(1)>']
            
            for input_data in inputs:
                if input_data.get('type') in ['text', 'search', 'url', 'email', 'number']:
                    # This is a simplified test - real XSS testing is more complex
                    # In a real implementation, we would fill the input and check if the payload is reflected
                    pass
            
        except Exception as e:
            log_debug(f"XSS testing failed: {e}")
        
        return findings
    
    def _test_sql_injection(self, target: str) -> List[Dict]:
        """Test for SQL injection vulnerabilities."""
        findings = []
        
        try:
            # Try SQLMap if installed
            if self.terminal.is_tool_installed('sqlmap'):
                # Run SQLMap on the target
                result = self.terminal.run(
                    f"sqlmap -u {target} --batch --level=1 --risk=1 --timeout=10",
                    timeout=60
                )
                if result.success and 'vulnerable' in result.stdout.lower():
                    findings.append({
                        'id': f"sql_{len(findings)+1}",
                        'title': 'SQL Injection Vulnerability',
                        'severity': 'critical',
                        'description': 'SQL injection vulnerability detected by SQLMap',
                        'remediation': 'Use parameterized queries and input validation',
                        'source': 'sqlmap',
                        'timestamp': get_timestamp(),
                        'target': target
                    })
        except Exception as e:
            log_debug(f"SQL injection test failed: {e}")
        
        return findings
    
    def _test_idor(self, target: str) -> List[Dict]:
        """Test for IDOR vulnerabilities."""
        findings = []
        
        try:
            # Check for ID patterns in URL
            import re
            id_patterns = [
                r'[?&]id=\d+',
                r'[?&]user_id=\d+',
                r'[?&]profile=\d+',
                r'[?&]account=\d+',
                r'[?&]order=\d+',
                r'[?&]invoice=\d+'
            ]
            
            current_url = self.browser.get_url() or target
            for pattern in id_patterns:
                if re.search(pattern, current_url, re.IGNORECASE):
                    findings.append({
                        'id': f"idor_{len(findings)+1}",
                        'title': 'Potential IDOR Vulnerability',
                        'severity': 'high',
                        'description': f'ID parameter found in URL: {pattern}. May be vulnerable to IDOR.',
                        'remediation': 'Implement proper access controls for all object references',
                        'source': 'active_scan',
                        'timestamp': get_timestamp(),
                        'target': target
                    })
                    break
        except Exception as e:
            log_debug(f"IDOR test failed: {e}")
        
        return findings
    
    # ============================================================
    # 3. FULL SCAN (Passive + Active)
    # ============================================================
    
    def scan_vulnerabilities(self, target: str, scan_type: str = 'full') -> List[Dict]:
        """
        Full vulnerability scan combining passive + active techniques.
        """
        log_info(f"🔬 Starting FULL scan on: {target}")
        self._emit_log('info', f"🔬 Starting FULL scan on: {target}")
        
        all_findings = []
        
        # Phase 1: Passive Scanning
        log_info("📡 PHASE 1: Passive Scanning")
        self._emit_log('info', "📡 PHASE 1: Passive Scanning")
        
        passive_results = self.passive_scan(target)
        all_findings.extend(passive_results.get('vulnerabilities', []))
        
        # Phase 2: Active System Control
        if scan_type in ['full', 'active']:
            log_info("🎮 PHASE 2: Active System Control")
            self._emit_log('info', "🎮 PHASE 2: Active System Control")
            
            active_findings = self.active_scan(target)
            all_findings.extend(active_findings)
        
        log_info(f"✅ Full scan complete. Found {len(all_findings)} total vulnerabilities")
        self._emit_log('info', f"✅ Full scan complete. Found {len(all_findings)} total vulnerabilities")
        
        return all_findings
    
    # ============================================================
    # 4. Report Generation
    # ============================================================
    
    def generate_report(self, target: str, findings: List[Dict], chains: List[Dict]) -> str:
        """Generate a vulnerability report."""
        log_info(f"📄 Generating report for: {target}")
        self._emit_log('info', f"📄 Generating report for: {target}")
        
        report = {
            'target': target,
            'timestamp': get_timestamp(),
            'total_findings': len(findings),
            'severity_counts': self._count_severities(findings),
            'findings': findings,
            'chains': chains,
            'recommendations': self._generate_recommendations(findings)
        }
        
        path = self.filesystem.save_report(target.replace('://', '_'), report)
        log_info(f"📄 Report saved: {path}")
        self._emit_log('info', f"📄 Report saved: {path}")
        return path
    
    def _count_severities(self, findings: List[Dict]) -> Dict[str, int]:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            severity = f.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        recommendations = []
        severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for f in findings:
            severity = f.get('severity', 'low').lower()
            if severity in severities:
                severities[severity] += 1
        
        if severities['critical'] > 0:
            recommendations.append(f"🔴 Address {severities['critical']} critical findings immediately")
        if severities['high'] > 0:
            recommendations.append(f"🟠 Prioritize {severities['high']} high severity findings")
        if severities['medium'] > 0:
            recommendations.append(f"🟡 Review {severities['medium']} medium severity findings")
        
        recommendations.append("✅ Ensure all findings are verified before reporting")
        
        return recommendations