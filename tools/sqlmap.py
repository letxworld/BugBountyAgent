"""
BugBountyAgent - SQLMap Tool Wrapper
======================================
Wrapper for SQLMap SQL injection detection and exploitation tool.
"""

import os
import subprocess
import json
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse

from core.config import Config
from core.utils import log_info, log_error, log_warning, log_debug


@dataclass
class SqlmapResult:
    """Result from a SQLMap scan."""
    url: str
    parameter: str
    technique: str  # U, S, E, B, T, Q
    payload: str
    dbms: Optional[str] = None
    database: Optional[str] = None
    tables: List[str] = None
    is_vulnerable: bool = False
    
    def __post_init__(self):
        if self.tables is None:
            self.tables = []


class SqlmapWrapper:
    """
    Wrapper for SQLMap SQL injection detection and exploitation tool.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.tool_config = config.get('tools.sqlmap', {})
        self.enabled = self.tool_config.get('enabled', True)
        self.path = self.tool_config.get('path', '/usr/local/bin/sqlmap')
        self.default_args = self.tool_config.get('args', '--batch --random-agent')
        self.risk = self.tool_config.get('risk', 2)
        self.level = self.tool_config.get('level', 2)
        
        self._available = None
        self._version = None
    
    def is_available(self) -> bool:
        """Check if SQLMap is installed and available."""
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
                log_info(f"✅ SQLMap {self._version} available at {self.path}")
            else:
                log_warning("SQLMap not available")
        except Exception as e:
            log_error(f"SQLMap check failed: {e}")
            self._available = False
        
        return self._available
    
    def get_version(self) -> Optional[str]:
        """Get SQLMap version."""
        if self.is_available():
            return self._version
        return None
    
    def scan(self, url: str, params: List[str] = None,
             method: str = 'GET', data: str = None,
             cookie: str = None, level: int = None,
             risk: int = None, timeout: int = 300) -> List[SqlmapResult]:
        """
        Scan a target for SQL injection vulnerabilities.
        
        Args:
            url: Target URL
            params: Parameters to test
            method: HTTP method (GET, POST, etc.)
            data: POST data
            cookie: Session cookie
            level: Scan level (1-5)
            risk: Scan risk (1-3)
            timeout: Scan timeout in seconds
            
        Returns:
            List[SqlmapResult]: Scan results
        """
        if not self.is_available():
            log_error("SQLMap not available")
            return []
        
        # Build command
        cmd = [self.path, '-u', url, '--batch', '--random-agent']
        
        # Add default args
        if self.default_args:
            cmd.extend(self.default_args.split())
        
        # Add method
        if method.upper() == 'POST' and data:
            cmd.extend(['--data', data])
        elif method.upper() == 'GET':
            cmd.append('--method=GET')
        
        # Add parameters to test
        if params:
            cmd.extend(['-p', ','.join(params)])
        
        # Add cookie
        if cookie:
            cmd.extend(['--cookie', cookie])
        
        # Add level and risk
        level = level or self.level
        risk = risk or self.risk
        cmd.extend(['--level', str(level), '--risk', str(risk)])
        
        # Add output format (JSON)
        cmd.extend(['--output-format', 'json'])
        
        log_info(f"💉 Scanning {url} for SQL injection")
        log_debug(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0 and result.stderr:
                log_warning(f"SQLMap had issues: {result.stderr[:200]}")
            
            return self._parse_output(result.stdout, url)
            
        except subprocess.TimeoutExpired:
            log_error(f"SQLMap scan timed out after {timeout}s")
            return []
        except Exception as e:
            log_error(f"SQLMap scan failed: {e}")
            return []
    
    def scan_get(self, url: str, params: List[str] = None) -> List[SqlmapResult]:
        """Scan a GET URL for SQL injection."""
        return self.scan(url, params, method='GET')
    
    def scan_post(self, url: str, data: str, params: List[str] = None) -> List[SqlmapResult]:
        """Scan a POST request for SQL injection."""
        return self.scan(url, params, method='POST', data=data)
    
    def _parse_output(self, output: str, target_url: str) -> List[SqlmapResult]:
        """Parse output from SQLMap."""
        results = []
        
        # Check if vulnerable
        is_vulnerable = 'vulnerable' in output.lower() or 'parameter' in output.lower()
        
        if not is_vulnerable:
            log_info("✅ No SQL injection vulnerabilities found")
            return results
        
        # Extract parameter information
        param_pattern = r'Parameter:\s*(\w+)'
        params = re.findall(param_pattern, output)
        
        # Extract technique
        tech_pattern = r'Technique:\s*(\w+)'
        techniques = re.findall(tech_pattern, output)
        
        # Extract DBMS
        dbms_pattern = r'DBMS:\s*(.+)'
        dbms_match = re.search(dbms_pattern, output)
        dbms = dbms_match.group(1).strip() if dbms_match else None
        
        # Extract database
        db_pattern = r'Database:\s*(\w+)'
        db_match = re.search(db_pattern, output)
        database = db_match.group(1) if db_match else None
        
        # Extract tables
        table_pattern = r'\+[\s-]+\+\s*\|\s*(\w+)\s*\|'
        tables = re.findall(table_pattern, output)
        
        # Build results
        for i, param in enumerate(params or ['unknown']):
            result = SqlmapResult(
                url=target_url,
                parameter=param,
                technique=techniques[i] if i < len(techniques) else 'U',
                payload='',
                dbms=dbms,
                database=database,
                tables=tables,
                is_vulnerable=True
            )
            results.append(result)
        
        log_info(f"🔴 SQLMap found {len(results)} vulnerabilities")
        return results
    
    def _parse_json_output(self, output: str) -> List[SqlmapResult]:
        """Parse JSON output from SQLMap (if available)."""
        results = []
        
        try:
            data = json.loads(output)
            # SQLMap JSON output format varies by version
            # This is a simplified parser
            if isinstance(data, dict):
                for key, value in data.items():
                    if 'vulnerable' in key.lower() and value:
                        results.append(SqlmapResult(
                            url='',
                            parameter=key,
                            technique='U',
                            payload='',
                            is_vulnerable=True
                        ))
            return results
        except json.JSONDecodeError:
            return self._parse_output(output, '')
    
    def get_results_as_dict(self, url: str) -> Dict[str, Any]:
        """Return scan results as a dictionary."""
        results = self.scan(url)
        
        return {
            'target': url,
            'total': len(results),
            'vulnerable': any(r.is_vulnerable for r in results),
            'results': [
                {
                    'parameter': r.parameter,
                    'technique': r.technique,
                    'dbms': r.dbms,
                    'database': r.database,
                    'tables': r.tables[:10] if r.tables else [],
                    'is_vulnerable': r.is_vulnerable
                }
                for r in results
            ]
        }