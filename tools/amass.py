"""
BugBountyAgent - Amass Tool Wrapper
=====================================
Wrapper for Amass subdomain enumeration tool.
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
class AmassResult:
    """Result from an Amass scan."""
    domain: str
    source: str  # Where the subdomain was found
    ip: Optional[str] = None
    resolved: Optional[str] = None


class AmassWrapper:
    """
    Wrapper for Amass subdomain enumeration tool.
    Supports passive and active enumeration.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.tool_config = config.get('tools.amass', {})
        self.enabled = self.tool_config.get('enabled', True)
        self.path = self.tool_config.get('path', '/usr/local/bin/amass')
        self.default_args = self.tool_config.get('args', '-passive')
        
        self._available = None
        self._version = None
    
    def is_available(self) -> bool:
        """Check if Amass is installed and available."""
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
                log_info(f"✅ Amass {self._version} available at {self.path}")
            else:
                log_warning("Amass not available")
        except Exception as e:
            log_error(f"Amass check failed: {e}")
            self._available = False
        
        return self._available
    
    def get_version(self) -> Optional[str]:
        """Get Amass version."""
        if self.is_available():
            return self._version
        return None
    
    def enumerate(self, domain: str, passive: bool = True,
                  active: bool = False, recursive: bool = False,
                  timeout: int = 300) -> List[AmassResult]:
        """
        Enumerate subdomains for a domain.
        
        Args:
            domain: Root domain (e.g., example.com)
            passive: Use passive enumeration only
            active: Use active enumeration (DNS brute force)
            recursive: Enable recursive discovery
            timeout: Scan timeout in seconds
            
        Returns:
            List[AmassResult]: Discovered subdomains
        """
        if not self.is_available():
            log_error("Amass not available")
            return []
        
        # Build command
        if passive:
            cmd = [self.path, 'enum', '-passive', '-d', domain]
        else:
            cmd = [self.path, 'enum', '-d', domain]
        
        # Add default args
        if self.default_args:
            cmd.extend(self.default_args.split())
        
        # Add active flag
        if active:
            cmd.append('-active')
        
        # Add recursive flag
        if recursive:
            cmd.append('-recursive')
        
        # Add JSON output
        cmd.extend(['-json'])
        
        log_info(f"🌐 Enumerating subdomains for: {domain}")
        log_debug(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0 and result.stderr:
                log_warning(f"Amass had issues: {result.stderr[:200]}")
            
            return self._parse_output(result.stdout, domain)
            
        except subprocess.TimeoutExpired:
            log_error(f"Amass scan timed out after {timeout}s")
            return []
        except Exception as e:
            log_error(f"Amass scan failed: {e}")
            return []
    
    def passive_enum(self, domain: str) -> List[AmassResult]:
        """Passive subdomain enumeration."""
        return self.enumerate(domain, passive=True, active=False)
    
    def active_enum(self, domain: str) -> List[AmassResult]:
        """Active subdomain enumeration (DNS brute force)."""
        return self.enumerate(domain, passive=False, active=True)
    
    def full_enum(self, domain: str) -> List[AmassResult]:
        """Full enumeration (passive + active + recursive)."""
        return self.enumerate(domain, passive=False, active=True, recursive=True)
    
    def _parse_output(self, output: str, domain: str) -> List[AmassResult]:
        """Parse JSON output from Amass."""
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
                # Try text parsing if JSON fails
                continue
        
        # Deduplicate by domain
        seen = set()
        unique_results = []
        for r in results:
            if r.domain not in seen:
                seen.add(r.domain)
                unique_results.append(r)
        
        log_info(f"✅ Amass found {len(unique_results)} subdomains for {domain}")
        return unique_results
    
    def _parse_single_result(self, data: Dict[str, Any]) -> Optional[AmassResult]:
        """Parse a single Amass JSON object."""
        try:
            return AmassResult(
                domain=data.get('name', ''),
                source=data.get('source', 'amass'),
                ip=data.get('addresses', [{}])[0].get('ip', None) if data.get('addresses') else None,
                resolved=data.get('resolved', None)
            )
        except Exception as e:
            log_debug(f"Failed to parse Amass result: {e}")
            return None
    
    def _parse_text_output(self, output: str, domain: str) -> List[AmassResult]:
        """Parse text output from Amass (fallback)."""
        results = []
        
        # Parse lines like: "example.com [Source: DNS, IP: 1.2.3.4]"
        pattern = r'(\S+\.\S+)\s+\[Source:\s*(\S+?)(?:\s*,\s*IP:\s*(\S+))?\]'
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            match = re.search(pattern, line)
            if match:
                domain_name = match.group(1)
                source = match.group(2) if match.group(2) else 'amass'
                ip = match.group(3) if match.group(3) else None
                
                results.append(AmassResult(
                    domain=domain_name,
                    source=source,
                    ip=ip
                ))
            else:
                # Simple line with domain only
                if line.strip() and '.' in line:
                    results.append(AmassResult(
                        domain=line.strip(),
                        source='amass'
                    ))
        
        return results
    
    def get_results_as_dict(self, domain: str) -> Dict[str, Any]:
        """Return enumeration results as a dictionary."""
        results = self.passive_enum(domain)
        
        return {
            'domain': domain,
            'total': len(results),
            'subdomains': [r.domain for r in results],
            'by_source': self._group_by_source(results),
            'results': [
                {
                    'domain': r.domain,
                    'source': r.source,
                    'ip': r.ip
                }
                for r in results
            ]
        }
    
    def _group_by_source(self, results: List[AmassResult]) -> Dict[str, int]:
        """Group subdomains by discovery source."""
        groups = {}
        for r in results:
            groups[r.source] = groups.get(r.source, 0) + 1
        return groups