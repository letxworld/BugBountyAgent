"""
BugBountyAgent - FFUF Tool Wrapper
====================================
Wrapper for FFUF (Fuzz Faster U Fool) directory and parameter fuzzing tool.
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
class FfufResult:
    """Result from an FFUF scan."""
    url: str
    status_code: int
    content_length: int
    redirect_location: Optional[str] = None
    response_time: Optional[float] = None
    lines: Optional[int] = None
    words: Optional[int] = None


class FfufWrapper:
    """
    Wrapper for FFUF directory and parameter fuzzing tool.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.tool_config = config.get('tools.ffuf', {})
        self.enabled = self.tool_config.get('enabled', True)
        self.path = self.tool_config.get('path', '/usr/local/bin/ffuf')
        self.wordlist = self.tool_config.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        self.threads = self.tool_config.get('threads', 40)
        
        self._available = None
        self._version = None
    
    def is_available(self) -> bool:
        """Check if FFUF is installed and available."""
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
                log_info(f"✅ FFUF {self._version} available at {self.path}")
            else:
                log_warning("FFUF not available")
        except Exception as e:
            log_error(f"FFUF check failed: {e}")
            self._available = False
        
        return self._available
    
    def get_version(self) -> Optional[str]:
        """Get FFUF version."""
        if self.is_available():
            return self._version
        return None
    
    def fuzz_directory(self, url: str, wordlist: Optional[str] = None,
                       extensions: List[str] = None, recursive: bool = False,
                       timeout: int = 300) -> List[FfufResult]:
        """
        Fuzz directories on a target.
        
        Args:
            url: Target URL (use FUZZ as placeholder for directory)
            wordlist: Path to wordlist
            extensions: File extensions to test (e.g., ['.php', '.html'])
            recursive: Enable recursive fuzzing
            timeout: Scan timeout in seconds
            
        Returns:
            List[FfufResult]: Discovered directories/files
        """
        if not self.is_available():
            log_error("FFUF not available")
            return []
        
        # Build command
        cmd = [self.path, '-u', url, '-w', wordlist or self.wordlist]
        
        # Add extensions
        if extensions:
            cmd.extend(['-e', ','.join(extensions)])
        
        # Add recursive flag
        if recursive:
            cmd.append('-recursion')
        
        # Add threads
        cmd.extend(['-t', str(self.threads)])
        
        # Add JSON output
        cmd.extend(['-of', 'json', '-o', '-'])
        
        log_info(f"🔍 Fuzzing directories on: {url}")
        log_debug(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0 and result.stderr:
                log_warning(f"FFUF had issues: {result.stderr[:200]}")
            
            return self._parse_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            log_error(f"FFUF scan timed out after {timeout}s")
            return []
        except Exception as e:
            log_error(f"FFUF scan failed: {e}")
            return []
    
    def fuzz_parameters(self, url: str, wordlist: Optional[str] = None,
                        timeout: int = 300) -> List[FfufResult]:
        """
        Fuzz parameters on a target.
        
        Args:
            url: Target URL with FUZZ placeholder for parameter
            wordlist: Path to wordlist
            timeout: Scan timeout in seconds
            
        Returns:
            List[FfufResult]: Discovered parameters
        """
        if not self.is_available():
            return []
        
        if wordlist is None:
            wordlist = '/usr/share/wordlists/dirb/common.txt'
        
        return self.fuzz_directory(url, wordlist, timeout=timeout)
    
    def fuzz_api(self, url: str, wordlist: Optional[str] = None,
                 timeout: int = 300) -> List[FfufResult]:
        """
        Fuzz API endpoints.
        
        Args:
            url: Target URL with FUZZ placeholder
            wordlist: Path to wordlist
            timeout: Scan timeout in seconds
            
        Returns:
            List[FfufResult]: Discovered API endpoints
        """
        if not self.is_available():
            return []
        
        if wordlist is None:
            wordlist = '/usr/share/wordlists/api/common.txt'
            if not os.path.exists(wordlist):
                wordlist = self.wordlist
        
        return self.fuzz_directory(url, wordlist, timeout=timeout)
    
    def _parse_output(self, output: str) -> List[FfufResult]:
        """Parse JSON output from FFUF."""
        results = []
        
        try:
            data = json.loads(output)
            results_data = data.get('results', [])
            
            for item in results_data:
                result = FfufResult(
                    url=item.get('url', ''),
                    status_code=item.get('status', 0),
                    content_length=item.get('length', 0),
                    redirect_location=item.get('redirectlocation', None),
                    response_time=item.get('time', None),
                    lines=item.get('lines', None),
                    words=item.get('words', None)
                )
                results.append(result)
            
            log_info(f"✅ FFUF found {len(results)} results")
            
        except json.JSONDecodeError:
            # Fallback to text parsing
            results = self._parse_text_output(output)
        
        return results
    
    def _parse_text_output(self, output: str) -> List[FfufResult]:
        """Parse text output from FFUF (fallback)."""
        results = []
        
        # Parse lines like: "http://example.com/admin [Status: 200, Size: 1234]"
        pattern = r'(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)\]'
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            match = re.search(pattern, line)
            if match:
                results.append(FfufResult(
                    url=match.group(1),
                    status_code=int(match.group(2)),
                    content_length=int(match.group(3))
                ))
        
        return results
    
    def filter_interesting(self, results: List[FfufResult]) -> List[FfufResult]:
        """Filter for interesting results (non-404 responses)."""
        interesting = []
        for r in results:
            if r.status_code not in [404, 403] and r.status_code < 500:
                interesting.append(r)
        return interesting
    
    def get_results_as_dict(self, url: str) -> Dict[str, Any]:
        """Return fuzzing results as a dictionary."""
        results = self.fuzz_directory(url)
        
        return {
            'target': url,
            'total': len(results),
            'by_status': self._group_by_status(results),
            'results': [
                {
                    'url': r.url,
                    'status_code': r.status_code,
                    'content_length': r.content_length,
                    'redirect_location': r.redirect_location
                }
                for r in results
            ]
        }
    
    def _group_by_status(self, results: List[FfufResult]) -> Dict[int, int]:
        """Group results by status code."""
        groups = {}
        for r in results:
            groups[r.status_code] = groups.get(r.status_code, 0) + 1
        return groups