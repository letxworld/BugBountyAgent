"""
BugBountyAgent - Vulnerability Scanner
========================================
Scans targets for vulnerabilities using multiple tools and techniques.
Performs reconnaissance, vulnerability detection, and exploitation.
"""

import json
import time
import subprocess
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse
import socket
import requests

from .config import Config
from .browser import BrowserController
from .terminal import TerminalController
from .filesystem import FileSystemController
from .logging import log_info, log_error, log_warning, log_debug, get_timestamp


class Scanner:
    """
    Vulnerability scanner that finds bugs autonomously.
    """
    
    def __init__(self, config: Config, browser: BrowserController, terminal: TerminalController):
        self.config = config
        self.browser = browser
        self.terminal = terminal
        self.filesystem = FileSystemController(config)
        
        self.timeout = config.get('scanner.timeout', 300)
        self.severity_filter = config.get('scanner.severity_filter', ['low', 'medium', 'high', 'critical'])
        
        log_info("🔍 Scanner initialized")
    
    # ============================================================
    # Reconnaissance
    # ============================================================
    
    def reconnaissance(self, target: str) -> Dict[str, Any]:
        """
        Perform reconnaissance on a target.
        
        Args:
            target: Target URL or IP
            
        Returns:
            Dict: Reconnaissance data
        """
        log_info(f"🔍 Reconnaissance on: {target}")
        
        results = {
            'target': target,
            'subdomains': [],
            'ports': [],
            'technologies': {},
            'dns': {},
            'ssl': {}
        }
        
        # Parse target
        parsed = urlparse(target)
        domain = parsed.netloc or target
        
        # 1. DNS Resolution
        try:
            ip = socket.gethostbyname(domain)
            results['dns']['ip'] = ip
            log_debug(f"   DNS: {domain} → {ip}")
        except:
            log_warning(f"   DNS resolution failed for: {domain}")
        
        # 2. Subdomain Discovery
        try:
            subdomains = self._discover_subdomains(domain)
            results['subdomains'] = subdomains[:20]  # Limit
            log_debug(f"   Found {len(subdomains)} subdomains")
        except Exception as e:
            log_warning(f"   Subdomain discovery failed: {e}")
        
        # 3. Port Scanning
        try:
            ports = self._scan_ports(domain)
            results['ports'] = ports
            log_debug(f"   Found {len(ports)} open ports")
        except Exception as e:
            log_warning(f"   Port scanning failed: {e}")
        
        # 4. Technology Detection
        try:
            tech = self._detect_technologies(target)
            results['technologies'] = tech
            log_debug(f"   Technologies: {', '.join(tech.keys())}")
        except Exception as e:
            log_warning(f"   Technology detection failed: {e}")
        
        # 5. SSL/TLS Information
        if parsed.scheme == 'https':
            try:
                ssl_info = self._get_ssl_info(domain)
                results['ssl'] = ssl_info
            except:
                pass
        
        # Save recon data
        self.filesystem.write_json(f"data/recon_{domain}.json", results)
        
        return results
    
    def _discover_subdomains(self, domain: str) -> List[str]:
        """Discover subdomains using multiple tools."""
        subdomains = []
        
        # Try Subfinder
        if self.terminal.is_tool_installed('subfinder'):
            result = self.terminal.run(f"subfinder -d {domain} -silent")
            if result.success:
                subdomains.extend([s.strip() for s in result.stdout.split('\n') if s.strip()])
        
        # Try Amass (passive)
        if self.terminal.is_tool_installed('amass'):
            result = self.terminal.run(f"amass enum -passive -d {domain}")
            if result.success:
                for line in result.stdout.split('\n'):
                    if '.' in line and domain in line:
                        subdomains.append(line.strip())
        
        # DNS bruteforce (common subdomains)
        common = ['www', 'mail', 'ftp', 'admin', 'dev', 'test', 'api', 'blog', 'shop', 'support']
        for sub in common:
            full = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full)
                subdomains.append(full)
            except:
                pass
        
        return list(set(subdomains))
    
    def _scan_ports(self, target: str) -> List[int]:
        """Scan for open ports."""
        ports = []
        
        # Use Nmap if available
        if self.terminal.is_tool_installed('nmap'):
            result = self.terminal.run(f"nmap -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,27017 -T4 {target}")
            if result.success:
                for line in result.stdout.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        try:
                            port = int(line.split('/')[0].strip())
                            ports.append(port)
                        except:
                            pass
        else:
            # Python fallback (top 10 ports)
            common_ports = [80, 443, 22, 21, 25, 3306, 5432, 8080, 8443, 27017]
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    if result == 0:
                        ports.append(port)
                except:
                    pass
        
        return ports
    
    def _detect_technologies(self, target: str) -> Dict[str, str]:
        """Detect technologies used by the target."""
        technologies = {}
        
        try:
            response = requests.get(target, timeout=10, verify=False)
            headers = response.headers
            
            # Server header
            if 'Server' in headers:
                technologies['server'] = headers['Server']
            
            # Content type
            if 'Content-Type' in headers:
                technologies['content_type'] = headers['Content-Type']
            
            # Powered by
            if 'X-Powered-By' in headers:
                technologies['powered_by'] = headers['X-Powered-By']
            
            # From response headers
            for key in ['X-Generator', 'X-AspNet-Version', 'X-GitHub-Request-Id']:
                if key in headers:
                    technologies[key] = headers[key]
            
            # From HTML meta tags
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                for meta in soup.find_all('meta'):
                    if meta.get('name') == 'generator':
                        technologies['generator'] = meta.get('content', '')
            except:
                pass
            
        except Exception as e:
            log_debug(f"Technology detection failed: {e}")
        
        return technologies
    
    def _get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL/TLS certificate information."""
        import ssl
        info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    info['not_before'] = cert.get('notBefore', '')
                    info['not_after'] = cert.get('notAfter', '')
                    info['valid'] = True
        except Exception as e:
            info['valid'] = False
            info['error'] = str(e)
        
        return info
    
    # ============================================================
    # Vulnerability Scanning
    # ============================================================
    
    def scan_vulnerabilities(self, target: str, scan_type: str = 'full') -> List[Dict]:
        """
        Scan for vulnerabilities.
        
        Args:
            target: Target URL
            scan_type: 'quick', 'full', 'recon'
            
        Returns:
            List[Dict]: Found vulnerabilities
        """
        log_info(f"🔬 Scanning for vulnerabilities: {target}")
        
        findings = []
        
        # Use Nuclei if available
        if self.terminal.is_tool_installed('nuclei'):
            nuclei_findings = self._run_nuclei(target)
            findings.extend(nuclei_findings)
        
        # Use Nikto if available
        if self.terminal.is_tool_installed('nikto'):
            nikto_findings = self._run_nikto(target)
            findings.extend(nikto_findings)
        
        # Use custom checks
        custom_findings = self._run_custom_checks(target)
        findings.extend(custom_findings)
        
        # Use browser-based testing (if not headless)
        if not self.config.get('browser.headless', False):
            browser_findings = self._run_browser_tests(target)
            findings.extend(browser_findings)
        
        # Filter by severity
        findings = [f for f in findings if f.get('severity', '').lower() in self.severity_filter]
        
        log_info(f"   Found {len(findings)} vulnerabilities")
        return findings
    
    def _run_nuclei(self, target: str) -> List[Dict]:
        """Run Nuclei vulnerability scanner."""
        findings = []
        
        severity_str = ','.join(self.severity_filter)
        cmd = f"nuclei -u {target} -severity {severity_str} -silent -json"
        
        result = self.terminal.run(cmd, timeout=120)
        if result.success:
            for line in result.stdout.split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        info = data.get('info', {})
                        finding = {
                            'title': info.get('name', 'Nuclei Finding'),
                            'severity': info.get('severity', 'medium'),
                            'description': info.get('description', ''),
                            'remediation': info.get('remediation', ''),
                            'cve_id': info.get('cve-id', ''),
                            'cvss_score': info.get('cvss-score', None),
                            'url': data.get('matched-at', target),
                            'source': 'nuclei',
                            'timestamp': get_timestamp()
                        }
                        findings.append(finding)
                    except:
                        pass
        
        return findings
    
    def _run_nikto(self, target: str) -> List[Dict]:
        """Run Nikto web scanner."""
        findings = []
        
        cmd = f"nikto -h {target} -Format json"
        result = self.terminal.run(cmd, timeout=120)
        
        if result.success:
            for line in result.stdout.split('\n'):
                if 'Vulnerability' in line or 'vulnerable' in line.lower():
                    finding = {
                        'title': line.strip()[:100],
                        'severity': 'medium',
                        'description': line.strip(),
                        'remediation': 'Review and fix identified issues',
                        'source': 'nikto',
                        'timestamp': get_timestamp()
                    }
                    findings.append(finding)
        
        return findings
    
    def _run_custom_checks(self, target: str) -> List[Dict]:
        """Run custom vulnerability checks."""
        findings = []
        
        try:
            response = requests.get(target, timeout=10, verify=False)
            headers = response.headers
            
            # Check for missing security headers
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
                    findings.append({
                        'title': f'Missing Security Header: {header}',
                        'severity': 'medium',
                        'description': desc,
                        'remediation': f'Add {header} header to server configuration',
                        'source': 'custom',
                        'timestamp': get_timestamp()
                    })
            
            # Check for sensitive information in response
            sensitive_patterns = [
                ('password', 'Potential password disclosure'),
                ('token', 'Potential token disclosure'),
                ('api_key', 'Potential API key disclosure'),
                ('secret', 'Potential secret disclosure'),
                ('debug', 'Debug information in response'),
                ('stack trace', 'Stack trace in response'),
            ]
            
            for pattern, desc in sensitive_patterns:
                if pattern.lower() in response.text.lower():
                    findings.append({
                        'title': f'Sensitive Information Disclosure: {pattern}',
                        'severity': 'high',
                        'description': desc,
                        'remediation': 'Remove sensitive information from responses',
                        'source': 'custom',
                        'timestamp': get_timestamp()
                    })
            
            # Check for directory listing
            if 'Directory listing for' in response.text or 'Index of /' in response.text:
                findings.append({
                    'title': 'Directory Listing Enabled',
                    'severity': 'medium',
                    'description': 'Directory listing is enabled, exposing file structure',
                    'remediation': 'Disable directory listing in server configuration',
                    'source': 'custom',
                    'timestamp': get_timestamp()
                })
            
            # Check for HTTP to HTTPS redirect
            if 'http://' in target:
                try:
                    response_http = requests.get(target, timeout=5, allow_redirects=False, verify=False)
                    if response_http.status_code in [301, 302]:
                        location = response_http.headers.get('Location', '')
                        if 'https' not in location.lower():
                            findings.append({
                                'title': 'Insecure HTTP Redirect',
                                'severity': 'medium',
                                'description': 'HTTP redirects to non-HTTPS location',
                                'remediation': 'Always redirect HTTP to HTTPS',
                                'source': 'custom',
                                'timestamp': get_timestamp()
                            })
                except:
                    pass
            
        except Exception as e:
            log_debug(f"Custom checks failed: {e}")
        
        return findings
    
    def _run_browser_tests(self, target: str) -> List[Dict]:
        """Run browser-based vulnerability tests."""
        findings = []
        
        if not self.browser.is_connected:
            self.browser.connect()
        
        if not self.browser.is_connected:
            return findings
        
        try:
            self.browser.navigate(target)
            time.sleep(2)
            
            # Check for XSS in forms
            forms = self.browser.evaluate("""
                () => {
                    const forms = [];
                    document.querySelectorAll('form').forEach(form => {
                        forms.push({
                            action: form.action,
                            method: form.method,
                            inputs: Array.from(form.querySelectorAll('input, textarea')).map(i => ({
                                type: i.type,
                                name: i.name,
                                id: i.id
                            }))
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
                        'title': 'Missing CSRF Protection',
                        'severity': 'high',
                        'description': f'Form at {form.get("action", "unknown")} missing CSRF token',
                        'remediation': 'Add CSRF tokens to all state-changing forms',
                        'source': 'browser',
                        'timestamp': get_timestamp()
                    })
            
            # Screenshot for evidence
            self.browser.screenshot('scan_evidence')
            
        except Exception as e:
            log_error(f"Browser tests failed: {e}")
        
        return findings
    
    # ============================================================
    # Report Generation
    # ============================================================
    
    def generate_report(self, target: str, findings: List[Dict], chains: List[Dict]) -> str:
        """
        Generate a vulnerability report.
        
        Args:
            target: Target URL
            findings: List of findings
            chains: List of attack chains
            
        Returns:
            str: Report file path
        """
        log_info(f"📄 Generating report for: {target}")
        
        report = {
            'target': target,
            'timestamp': get_timestamp(),
            'total_findings': len(findings),
            'severity_counts': self._count_severities(findings),
            'findings': findings,
            'chains': chains,
            'recommendations': self._generate_recommendations(findings)
        }
        
        # Save report
        path = self.filesystem.save_report(target.replace('://', '_'), report)
        
        # Also generate markdown report
        md_path = path.replace('.json', '.md')
        md_content = self._generate_markdown_report(report)
        self.filesystem.write_file(md_path, md_content)
        
        return path
    
    def _count_severities(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            severity = f.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate remediation recommendations."""
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
        if severities['low'] > 0:
            recommendations.append(f"🔵 Consider {severities['low']} low severity findings")
        
        recommendations.append("✅ Ensure all findings are verified before reporting")
        recommendations.append("📋 Follow responsible disclosure guidelines")
        
        return recommendations
    
    def _generate_markdown_report(self, report: Dict) -> str:
        """Generate markdown report."""
        md = f"""# Bug Bounty Report

## Target
**{report['target']}**

**Date:** {report['timestamp']}

## Summary
- **Total Findings:** {report['total_findings']}
- **Critical:** {report['severity_counts'].get('critical', 0)}
- **High:** {report['severity_counts'].get('high', 0)}
- **Medium:** {report['severity_counts'].get('medium', 0)}
- **Low:** {report['severity_counts'].get('low', 0)}

## Recommendations
"""
        for rec in report.get('recommendations', []):
            md += f"- {rec}\n"
        
        md += "\n## Findings\n\n"
        
        for i, f in enumerate(report['findings'], 1):
            md += f"### {i}. {f.get('title', 'Unknown')}\n"
            md += f"- **Severity:** {f.get('severity', 'unknown').upper()}\n"
            md += f"- **Description:** {f.get('description', 'No description')}\n"
            md += f"- **Remediation:** {f.get('remediation', 'Not provided')}\n"
            if f.get('cve_id'):
                md += f"- **CVE:** {f.get('cve_id')}\n"
            md += f"- **Source:** {f.get('source', 'unknown')}\n"
            md += "\n---\n\n"
        
        return md