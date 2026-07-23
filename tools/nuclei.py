"""
BugBountyAgent - Nuclei Tool Wrapper
======================================
Wrapper for Nuclei vulnerability scanner.
"""

import os
import subprocess
import json
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from core.config import Config
from core.utils import log_info, log_error, log_warning, log_debug


@dataclass
class NucleiResult:
    """Result from a Nuclei scan."""
    template_id: str
    template_name: str
    severity: str  # critical, high, medium, low, info
    description: str
    remediation: str
    matched_at: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    curl_command: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)


class NucleiWrapper:
    """
    Wrapper for Nuclei vulnerability scanner.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.tool_config = config.get('tools.nuclei', {})
        self.enabled = self.tool_config.get('enabled', True)
        self.path = self.tool_config.get('path', '/usr/local/bin/nuclei')
        self.default_args = self.tool_config.get('args', '-severity low,medium,high,critical')
        
        self._available = None
        self._version = None
    
    def is_available(self) -> bool:
        """Check if Nuclei is installed and available."""
        if self._available is not None:
            return self._available
        
        try:
            result = subprocess.run(
                [self.path, '-version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            self._available = result.returncode == 0
            if self._available:
                lines = result.stdout.strip().split('\n')
                self._version = lines[0] if lines else 'unknown'
                log_info(f"✅ Nuclei {self._version} available at {self.path}")
            else:
                log_warning("Nuclei not available")
        except Exception as e:
            log_error(f"Nuclei check failed: {e}")
            self._available = False
        
        return self._available
    
    def get_version(self) -> Optional[str]:
        """Get Nuclei version."""
        if self.is_available():
            return self._version
        return None
    
    def scan(self, target: str, severity: List[str] = None,
             tags: List[str] = None, include_templates: List[str] = None,
             exclude_templates: List[str] = None, timeout: int = 300) -> List[NucleiResult]:
        """
        Run a Nuclei scan on a target.
        
        Args:
            target: Target URL or IP
            severity: List of severities to include
            tags: List of tags to include
            include_templates: Specific templates to include
            exclude_templates: Specific templates to exclude
            timeout: Scan timeout in seconds
            
        Returns:
            List[NucleiResult]: Scan results
        """
        if not self.is_available():
            log_error("Nuclei not available")
            return []
        
        # Build command
        cmd = [self.path, '-target', target, '-json', '-silent']
        
        # Add severity filter
        if severity:
            cmd.extend(['-severity', ','.join(severity)])
        else:
            # Use default severity filter from config
            default_severity = self.config.get('scanner.severity_filter', ['low', 'medium', 'high', 'critical'])
            cmd.extend(['-severity', ','.join(default_severity)])
        
        # Add tags filter
        if tags:
            cmd.extend(['-tags', ','.join(tags)])
        
        # Add include/exclude templates
        if include_templates:
            cmd.extend(['-templates', ','.join(include_templates)])
        
        if exclude_templates:
            for template in exclude_templates:
                cmd.extend(['-exclude-template', template])
        
        # Add rate limit
        rate_limit = self.config.get('tools.nuclei.rate_limit', 50)
        cmd.extend(['-rl', str(rate_limit)])
        
        log_info(f"🔬 Running Nuclei scan on {target}")
        log_debug(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0 and result.stderr:
                log_warning(f"Nuclei had issues: {result.stderr[:200]}")
            
            return self._parse_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            log_error(f"Nuclei scan timed out after {timeout}s")
            return []
        except Exception as e:
            log_error(f"Nuclei scan failed: {e}")
            return []
    
    def scan_web(self, url: str) -> List[NucleiResult]:
        """Scan a web target."""
        return self.scan(url)
    
    def scan_network(self, ip: str) -> List[NucleiResult]:
        """Scan a network target."""
        return self.scan(ip, severity=['medium', 'high', 'critical'])
    
    def _parse_output(self, output: str) -> List[NucleiResult]:
        """Parse JSON output from Nuclei."""
        results = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                result = self._parse_single_result(data)
                if result:
                    results.append(result)
            except json.JSONDecodeError:
                continue
        
        log_info(f"✅ Nuclei found {len(results)} vulnerabilities")
        return results
    
    def _parse_single_result(self, data: Dict[str, Any]) -> Optional[NucleiResult]:
        """Parse a single Nuclei JSON object."""
        try:
            info = data.get('info', {})
            
            return NucleiResult(
                template_id=data.get('template-id', ''),
                template_name=info.get('name', 'Unknown Vulnerability'),
                severity=info.get('severity', 'info').lower(),
                description=info.get('description', 'No description available'),
                remediation=info.get('remediation', 'No remediation provided'),
                matched_at=data.get('matched-at', ''),
                cve_id=info.get('cve-id', ''),
                cvss_score=info.get('cvss-score', None),
                tags=info.get('tags', []),
                curl_command=data.get('curl-command', ''),
                raw_data=data
            )
        except Exception as e:
            log_debug(f"Failed to parse Nuclei result: {e}")
            return None
    
    def list_templates(self) -> List[Dict[str, Any]]:
        """List available Nuclei templates."""
        if not self.is_available():
            return []
        
        try:
            cmd = [self.path, '-list-templates']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                return []
            
            templates = []
            for line in result.stdout.strip().split('\n'):
                if line.strip() and not line.startswith('['):
                    parts = line.split()
                    if len(parts) >= 2:
                        templates.append({
                            'name': parts[0],
                            'severity': parts[1] if len(parts) > 1 else 'info',
                            'path': ' '.join(parts[2:]) if len(parts) > 2 else ''
                        })
            
            return templates
            
        except Exception as e:
            log_error(f"Failed to list templates: {e}")
            return []
    
    def update_templates(self) -> bool:
        """Update Nuclei templates."""
        if not self.is_available():
            return False
        
        try:
            cmd = [self.path, '-update-templates']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                log_info("✅ Nuclei templates updated")
                return True
            else:
                log_error(f"Failed to update templates: {result.stderr[:200]}")
                return False
        except Exception as e:
            log_error(f"Failed to update templates: {e}")
            return False
    
    def get_template_count(self) -> int:
        """Get the number of available templates."""
        templates = self.list_templates()
        return len(templates)
    
    def get_results_as_dict(self, target: str) -> Dict[str, Any]:
        """Return scan results as a dictionary."""
        results = self.scan(target)
        
        if not results:
            return {'target': target, 'total': 0, 'vulnerabilities': []}
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for r in results:
            if r.severity in severity_counts:
                severity_counts[r.severity] += 1
        
        return {
            'target': target,
            'total': len(results),
            'severity_counts': severity_counts,
            'vulnerabilities': [
                {
                    'template_id': r.template_id,
                    'name': r.template_name,
                    'severity': r.severity,
                    'description': r.description[:200],
                    'remediation': r.remediation[:200],
                    'cve_id': r.cve_id,
                    'cvss_score': r.cvss_score,
                    'url': r.matched_at,
                    'tags': r.tags
                }
                for r in results
            ]
        }