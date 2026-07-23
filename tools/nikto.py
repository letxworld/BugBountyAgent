"""
BugBountyAgent - Nikto Tool Wrapper
=====================================
Wrapper for Nikto web server vulnerability scanner.
"""

import os
import subprocess
import json
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

from core.config import Config
from core.utils import log_info, log_error, log_warning, log_debug


@dataclass
class NiktoResult:
    """Result from a Nikto scan."""
    target: str
    port: int
    method: str
    path: str
    description: str
    severity: str  # 0: info, 1: low, 2: medium, 3: high
    osvdb_id: Optional[str] = None
    cve_id: Optional[str] = None
    nvd_id: Optional[str] = None


class NiktoWrapper:
    """
    Wrapper for Nikto web server vulnerability scanner.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.tool_config = config.get('tools.nikto', {})
        self.enabled = self.tool_config.get('enabled', True)
        self.path = self.tool_config.get('path', '/usr/local/bin/nikto')
        self.default_args = self.tool_config.get('args', '-ssl -h')
        
        self._available = None
        self._version = None
    
    def is_available(self) -> bool:
        """Check if Nikto is installed and available."""
        if self._available is not None:
            return self._available
        
        try:
            result = subprocess.run(
                [self.path, '-Version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            self._available = result.returncode == 0
            if self._available:
                lines = result.stdout.strip().split('\n')
                self._version = lines[0] if lines else 'unknown'
                log_info(f"✅ Nikto {self._version} available at {self.path}")
            else:
                log_warning("Nikto not available")
        except Exception as e:
            log_error(f"Nikto check failed: {e}")
            self._available = False
        
        return self._available
    
    def get_version(self) -> Optional[str]:
        """Get Nikto version."""
        if self.is_available():
            return self._version
        return None
    
    def scan(self, target: str, port: int = 443, ssl: bool = True,
             timeout: int = 300) -> List[NiktoResult]:
        """
        Scan a target with Nikto.
        
        Args:
            target: Target host or URL
            port: Port to scan
            ssl: Use SSL/TLS
            timeout: Scan timeout in seconds
            
        Returns:
            List[NiktoResult]: Scan results
        """
        if not self.is_available():
            log_error("Nikto not available")
            return []
        
        # Build command
        cmd = [self.path, '-h', target]
        
        # Add port
        if port:
            cmd.extend(['-p', str(port)])
        
        # Add SSL flag
        if ssl:
            cmd.append('-ssl')
        
        # Add default args
        if self.default_args:
            cmd.extend(self.default_args.split())
        
        # Add output format (JSON)
        cmd.extend(['-Format', 'json'])
        
        # Add timeout
        cmd.extend(['-timeout', str(timeout)])
        
        # Add user agent
        cmd.extend(['-ua', 'BugBountyAgent/0.1.0'])
        
        log_info(f"🌐 Scanning {target} with Nikto")
        log_debug(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30
            )
            
            if result.returncode != 0 and result.stderr:
                log_warning(f"Nikto had issues: {result.stderr[:200]}")
            
            return self._parse_output(result.stdout, target)
            
        except subprocess.TimeoutExpired:
            log_error(f"Nikto scan timed out after {timeout}s")
            return []
        except Exception as e:
            log_error(f"Nikto scan failed: {e}")
            return []
    
    def scan_web(self, url: str) -> List[NiktoResult]:
        """Scan a web target."""
        parsed = urlparse(url)
        target = parsed.netloc
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        ssl = parsed.scheme == 'https'
        
        return self.scan(target, port, ssl)
    
    def _parse_output(self, output: str, target: str) -> List[NiktoResult]:
        """Parse JSON output from Nikto."""
        results = []
        
        try:
            # Try to parse as JSON
            data = json.loads(output)
            
            for item in data.get('vulnerabilities', []):
                result = NiktoResult(
                    target=target,
                    port=item.get('port', 443),
                    method=item.get('method', 'GET'),
                    path=item.get('path', ''),
                    description=item.get('description', ''),
                    severity=str(item.get('severity', 1)),
                    osvdb_id=item.get('osvdb_id', ''),
                    cve_id=item.get('cve_id', ''),
                    nvd_id=item.get('nvd_id', '')
                )
                results.append(result)
                
        except json.JSONDecodeError:
            # Fallback to text parsing
            results = self._parse_text_output(output, target)
        
        log_info(f"✅ Nikto found {len(results)} vulnerabilities")
        return results
    
    def _parse_text_output(self, output: str, target: str) -> List[NiktoResult]:
        """Parse text output from Nikto (fallback)."""
        results = []
        
        patterns = [
            (r'\+ (.*?)(?:\s*\(OSVDB-\d+\))?\s*:?\s*(.*?)(?:\s*\[http[s]?://\S+\])?$', 1),
            (r'\+ (.*?)\s*\(OSVDB-\d+\)\s*:\s*(.*?)$', 2),
        ]
        
        for line in output.strip().split('\n'):
            if not line.strip() or line.startswith('-') or line.startswith('='):
                continue
            
            for pattern, _ in patterns:
                match = re.search(pattern, line)
                if match:
                    desc = match.group(1).strip()
                    detail = match.group(2).strip() if match.lastindex >= 2 else ''
                    
                    # Determine severity
                    severity = '1'  # default low
                    if 'critical' in desc.lower() or 'high' in desc.lower():
                        severity = '3'
                    elif 'medium' in desc.lower():
                        severity = '2'
                    elif 'info' in desc.lower():
                        severity = '0'
                    
                    results.append(NiktoResult(
                        target=target,
                        port=443,
                        method='GET',
                        path='',
                        description=f"{desc}: {detail}" if detail else desc,
                        severity=severity
                    ))
                    break
        
        return results
    
    def get_results_as_dict(self, url: str) -> Dict[str, Any]:
        """Return scan results as a dictionary."""
        results = self.scan_web(url)
        
        return {
            'target': url,
            'total': len(results),
            'by_severity': self._group_by_severity(results),
            'results': [
                {
                    'path': r.path,
                    'description': r.description[:200],
                    'severity': r.severity,
                    'cve_id': r.cve_id,
                    'osvdb_id': r.osvdb_id
                }
                for r in results
            ]
        }
    
    def _group_by_severity(self, results: List[NiktoResult]) -> Dict[str, int]:
        """Group results by severity."""
        groups = {'0': 0, '1': 0, '2': 0, '3': 0}
        for r in results:
            if r.severity in groups:
                groups[r.severity] += 1
        return groups