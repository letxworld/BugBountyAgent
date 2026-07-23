"""
BugBountyAgent - Subfinder Tool Wrapper
=========================================
Wrapper for Subfinder subdomain discovery tool.
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
class SubfinderResult:
    """Result from a Subfinder scan."""
    domain: str
    source: str  # Where the subdomain was found


class SubfinderWrapper:
    """
    Wrapper for Subfinder subdomain discovery tool.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.tool_config = config.get('tools.subfinder', {})
        self.enabled = self.tool_config.get('enabled', True)
        self.path = self.tool_config.get('path', '/usr/local/bin/subfinder')
        self.default_args = self.tool_config.get('args', '-silent')
        self.sources = self.tool_config.get('sources', 'all')
        
        self._available = None
        self._version = None
    
    def is_available(self) -> bool:
        """Check if Subfinder is installed and available."""
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
                log_info(f"✅ Subfinder {self._version} available at {self.path}")
            else:
                log_warning("Subfinder not available")
        except Exception as e:
            log_error(f"Subfinder check failed: {e}")
            self._available = False
        
        return self._available
    
    def get_version(self) -> Optional[str]:
        """Get Subfinder version."""
        if self.is_available():
            return self._version
        return None
    
    def discover(self, domain: str, sources: List[str] = None,
                 recursive: bool = True, timeout: int = 120) -> List[SubfinderResult]:
        """
        Discover subdomains for a domain.
        
        Args:
            domain: Root domain (e.g., example.com)
            sources: List of sources to use
            recursive: Enable recursive discovery
            timeout: Scan timeout in seconds
            
        Returns:
            List[SubfinderResult]: Discovered subdomains
        """
        if not self.is_available():
            log_error("Subfinder not available")
            return []
        
        # Build command
        cmd = [self.path, '-d', domain]
        
        # Add default args
        if self.default_args:
            cmd.extend(self.default_args.split())
        
        # Add sources
        if sources:
            cmd.extend(['-sources', ','.join(sources)])
        elif self.sources != 'all':
            cmd.extend(['-sources', self.sources])
        
        # Add recursive flag
        if recursive:
            cmd.append('-recursive')
        
        # Add JSON output format
        cmd.extend(['-o', 'json'])
        
        log_info(f"🌐 Discovering subdomains for: {domain}")
        log_debug(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0 and result.stderr:
                log_warning(f"Subfinder had issues: {result.stderr[:200]}")
            
            return self._parse_output(result.stdout, result.stderr, domain)
            
        except subprocess.TimeoutExpired:
            log_error(f"Subfinder scan timed out after {timeout}s")
            return []
        except Exception as e:
            log_error(f"Subfinder scan failed: {e}")
            return []
    
    def passive_discover(self, domain: str) -> List[SubfinderResult]:
        """Passive subdomain discovery."""
        return self.discover(domain, sources=['passive'])
    
    def all_sources_discover(self, domain: str) -> List[SubfinderResult]:
        """Discover using all sources."""
        return self.discover(domain, sources=None)
    
    def _parse_output(self, stdout: str, stderr: str, domain: str) -> List[SubfinderResult]:
        """Parse output from Subfinder."""
        results = []
        sources = []
        
        # Try to parse JSON output
        try:
            data = json.loads(stdout)
            if 'host' in data:
                results.append(SubfinderResult(
                    domain=data['host'],
                    source='subfinder'
                ))
            return results
        except json.JSONDecodeError:
            pass
        
        # Parse line by line (plain text output)
        for line in stdout.strip().split('\n'):
            if line.strip() and not line.startswith('['):
                parts = line.split()
                if len(parts) >= 2:
                    domain_name = parts[0]
                    source = parts[1] if len(parts) > 1 else 'unknown'
                else:
                    domain_name = line.strip()
                    source = 'subfinder'
                
                results.append(SubfinderResult(
                    domain=domain_name,
                    source=source
                ))
        
        # Extract sources from stderr if available
        for line in stderr.strip().split('\n'):
            if 'Enabled sources:' in line:
                sources = line.replace('Enabled sources:', '').strip().split()
                break
        
        log_info(f"✅ Subfinder found {len(results)} subdomains for {domain}")
        return results
    
    def list_sources(self) -> List[str]:
        """List available Subfinder sources."""
        if not self.is_available():
            return []
        
        try:
            cmd = [self.path, '-ls']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return []
            
            sources = []
            for line in result.stdout.strip().split('\n'):
                if line.strip() and not line.startswith('['):
                    sources.append(line.strip())
            
            return sources
            
        except Exception as e:
            log_error(f"Failed to list sources: {e}")
            return []
    
    def get_results_as_dict(self, domain: str) -> Dict[str, Any]:
        """Return discovery results as a dictionary."""
        results = self.discover(domain)
        
        return {
            'domain': domain,
            'total': len(results),
            'subdomains': [r.domain for r in results],
            'sources': {r.domain: r.source for r in results},
            'results': [
                {
                    'domain': r.domain,
                    'source': r.source
                }
                for r in results
            ]
        }