"""
BugBountyAgent - WPScan Tool Wrapper
======================================
Wrapper for WPScan WordPress vulnerability scanner.
"""

import os
import subprocess
import json
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from core.config import Config
from core.utils import log_info, log_error, log_warning, log_debug


@dataclass
class WpscanResult:
    """Result from a WPScan scan."""
    type: str  # vulnerability, theme, plugin, user, wordpress
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None  # critical, high, medium, low
    cve_id: Optional[str] = None
    fixed_in: Optional[str] = None
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []


class WpscanWrapper:
    """
    Wrapper for WPScan WordPress vulnerability scanner.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.tool_config = config.get('tools.wpscan', {})
        self.enabled = self.tool_config.get('enabled', True)
        self.path = self.tool_config.get('path', '/usr/local/bin/wpscan')
        self.default_args = self.tool_config.get('args', '--rua -e vp,vt,tt')
        
        self._available = None
        self._version = None
    
    def is_available(self) -> bool:
        """Check if WPScan is installed and available."""
        if self._available is not None:
            return self._available
        
        try:
            result = subprocess.run(
                [self.path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            self._available = result.returncode == 0
            if self._available:
                lines = result.stdout.strip().split('\n')
                self._version = lines[0] if lines else 'unknown'
                log_info(f"✅ WPScan {self._version} available at {self.path}")
            else:
                log_warning("WPScan not available")
        except Exception as e:
            log_error(f"WPScan check failed: {e}")
            self._available = False
        
        return self._available
    
    def get_version(self) -> Optional[str]:
        """Get WPScan version."""
        if self.is_available():
            return self._version
        return None
    
    def scan(self, url: str, enumerate_all: bool = True,
             enumerate_users: bool = True, enumerate_plugins: bool = True,
             enumerate_themes: bool = True, timeout: int = 600) -> List[WpscanResult]:
        """
        Scan a WordPress target with WPScan.
        
        Args:
            url: Target URL
            enumerate_all: Enumerate everything
            enumerate_users: Enumerate users
            enumerate_plugins: Enumerate plugins
            enumerate_themes: Enumerate themes
            timeout: Scan timeout in seconds
            
        Returns:
            List[WpscanResult]: Scan results
        """
        if not self.is_available():
            log_error("WPScan not available")
            return []
        
        # Build command
        cmd = [self.path, '--url', url, '--format', 'json']
        
        # Add default args
        if self.default_args:
            cmd.extend(self.default_args.split())
        
        # Add enumeration
        if enumerate_all:
            cmd.extend(['-e', 'ap,at,u,vp,vt'])
        else:
            enumeration = []
            if enumerate_plugins:
                enumeration.append('p')
            if enumerate_themes:
                enumeration.append('t')
            if enumerate_users:
                enumeration.append('u')
            if enumeration:
                cmd.extend(['-e', ','.join(enumeration)])
        
        # Add update flag
        cmd.append('--update')
        
        log_info(f"🔍 Scanning WordPress target: {url}")
        log_debug(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0 and result.stderr:
                log_warning(f"WPScan had issues: {result.stderr[:200]}")
            
            return self._parse_output(result.stdout, url)
            
        except subprocess.TimeoutExpired:
            log_error(f"WPScan scan timed out after {timeout}s")
            return []
        except Exception as e:
            log_error(f"WPScan scan failed: {e}")
            return []
    
    def scan_vulnerabilities(self, url: str) -> List[WpscanResult]:
        """Scan for WordPress vulnerabilities only."""
        return self.scan(url, enumerate_all=False)
    
    def enumerate_plugins(self, url: str) -> List[WpscanResult]:
        """Enumerate installed plugins."""
        return self.scan(url, enumerate_plugins=True, enumerate_all=False)
    
    def enumerate_users(self, url: str) -> List[WpscanResult]:
        """Enumerate WordPress users."""
        return self.scan(url, enumerate_users=True, enumerate_all=False)
    
    def _parse_output(self, output: str, url: str) -> List[WpscanResult]:
        """Parse JSON output from WPScan."""
        results = []
        
        try:
            data = json.loads(output)
            
            # Parse vulnerabilities
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    # Plugin vulnerabilities
                    if 'plugin' in vuln:
                        for item in vuln.get('vulnerabilities', []):
                            results.append(WpscanResult(
                                type='plugin',
                                name=vuln['plugin'],
                                version=vuln.get('version', ''),
                                description=item.get('description', ''),
                                severity=item.get('severity', ''),
                                cve_id=item.get('cve_id', ''),
                                fixed_in=item.get('fixed_in', ''),
                                references=item.get('references', [])
                            ))
                    
                    # Theme vulnerabilities
                    elif 'theme' in vuln:
                        for item in vuln.get('vulnerabilities', []):
                            results.append(WpscanResult(
                                type='theme',
                                name=vuln['theme'],
                                version=vuln.get('version', ''),
                                description=item.get('description', ''),
                                severity=item.get('severity', ''),
                                cve_id=item.get('cve_id', ''),
                                fixed_in=item.get('fixed_in', ''),
                                references=item.get('references', [])
                            ))
                    
                    # WordPress core vulnerabilities
                    elif 'wordpress' in vuln:
                        for item in vuln.get('vulnerabilities', []):
                            results.append(WpscanResult(
                                type='wordpress',
                                name='WordPress Core',
                                version=vuln.get('version', ''),
                                description=item.get('description', ''),
                                severity=item.get('severity', ''),
                                cve_id=item.get('cve_id', ''),
                                fixed_in=item.get('fixed_in', ''),
                                references=item.get('references', [])
                            ))
            
            # Parse users
            if 'users' in data:
                for user in data['users']:
                    results.append(WpscanResult(
                        type='user',
                        name=user.get('username', ''),
                        description=f"User found: {user.get('username')}",
                        severity='info'
                    ))
            
            # Parse plugins
            if 'plugins' in data:
                for plugin, info in data['plugins'].items():
                    results.append(WpscanResult(
                        type='plugin',
                        name=plugin,
                        version=info.get('version', ''),
                        description=f"Plugin found: {plugin}",
                        severity='info'
                    ))
            
            # Parse themes
            if 'themes' in data:
                for theme, info in data['themes'].items():
                    results.append(WpscanResult(
                        type='theme',
                        name=theme,
                        version=info.get('version', ''),
                        description=f"Theme found: {theme}",
                        severity='info'
                    ))
            
            # Parse WordPress version
            if 'version' in data:
                results.append(WpscanResult(
                    type='wordpress',
                    name='WordPress Version',
                    version=data['version'],
                    description=f"WordPress {data['version']} detected",
                    severity='info'
                ))
            
        except json.JSONDecodeError:
            # Fallback to text parsing
            results = self._parse_text_output(output, url)
        
        log_info(f"✅ WPScan found {len(results)} results")
        return results
    
    def _parse_text_output(self, output: str, url: str) -> List[WpscanResult]:
        """Parse text output from WPScan (fallback)."""
        results = []
        
        # Parse WordPress version
        version_match = re.search(r'WordPress version\s+(\d+\.\d+(?:\.\d+)?)', output)
        if version_match:
            results.append(WpscanResult(
                type='wordpress',
                name='WordPress Version',
                version=version_match.group(1),
                description=f"WordPress {version_match.group(1)} detected",
                severity='info'
            ))
        
        # Parse user enumeration
        user_pattern = r'\|\s*ID\s*\|\s*(\w+)\s*\|'
        for match in re.finditer(user_pattern, output):
            username = match.group(1)
            if username:
                results.append(WpscanResult(
                    type='user',
                    name=username,
                    description=f"User found: {username}",
                    severity='info'
                ))
        
        # Parse vulnerabilities
        vuln_pattern = r'\[!\]\s*(.*?)(?:\s*vulnerability\s*)?:\s*(.*?)(?:\n|$)'
        for match in re.finditer(vuln_pattern, output):
            name = match.group(1).strip()
            description = match.group(2).strip()
            
            # Determine type
            if 'plugin' in name.lower():
                type_name = 'plugin'
            elif 'theme' in name.lower():
                type_name = 'theme'
            else:
                type_name = 'vulnerability'
            
            # Determine severity
            severity = 'medium'
            if 'critical' in description.lower():
                severity = 'critical'
            elif 'high' in description.lower():
                severity = 'high'
            elif 'low' in description.lower():
                severity = 'low'
            
            results.append(WpscanResult(
                type=type_name,
                name=name,
                version='',
                description=description,
                severity=severity
            ))
        
        return results
    
    def get_results_as_dict(self, url: str) -> Dict[str, Any]:
        """Return scan results as a dictionary."""
        results = self.scan(url)
        
        by_type = {}
        for r in results:
            by_type[r.type] = by_type.get(r.type, 0) + 1
        
        return {
            'target': url,
            'total': len(results),
            'by_type': by_type,
            'results': [
                {
                    'type': r.type,
                    'name': r.name,
                    'version': r.version,
                    'severity': r.severity or 'info',
                    'description': r.description[:100] if r.description else '',
                    'cve_id': r.cve_id
                }
                for r in results
            ]
        }