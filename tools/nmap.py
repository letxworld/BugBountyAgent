"""
BugBountyAgent - Nmap Tool Wrapper
====================================
Wrapper for Nmap port scanning and service detection.
"""

import os
import subprocess
import re
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from core.config import Config
from core.utils import log_info, log_error, log_warning, log_debug


@dataclass
class NmapResult:
    """Result from an Nmap scan."""
    target: str
    status: str  # up, down, unknown
    hostname: Optional[str] = None
    os: Optional[str] = None
    ports: List[Dict[str, Any]] = field(default_factory=list)
    scripts: List[Dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""


class NmapWrapper:
    """
    Wrapper for Nmap port scanning and service detection.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.tool_config = config.get('tools.nmap', {})
        self.enabled = self.tool_config.get('enabled', True)
        self.path = self.tool_config.get('path', '/usr/bin/nmap')
        self.default_args = self.tool_config.get('args', '-sV -sC -O -T4')
        
        self._available = None
        self._version = None
    
    def is_available(self) -> bool:
        """Check if Nmap is installed and available."""
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
                # Extract version
                match = re.search(r'Nmap version (\d+\.\d+)', result.stdout)
                self._version = match.group(1) if match else 'unknown'
                log_info(f"✅ Nmap {self._version} available at {self.path}")
            else:
                log_warning("Nmap not available")
        except Exception as e:
            log_error(f"Nmap check failed: {e}")
            self._available = False
        
        return self._available
    
    def get_version(self) -> Optional[str]:
        """Get Nmap version."""
        if self.is_available():
            return self._version
        return None
    
    def scan(self, target: str, ports: Optional[List[int]] = None,
             args: Optional[str] = None, timeout: int = 300) -> Optional[NmapResult]:
        """
        Run an Nmap scan on a target.
        
        Args:
            target: IP address or hostname
            ports: List of ports to scan (optional)
            args: Additional Nmap arguments (optional)
            timeout: Scan timeout in seconds
            
        Returns:
            Optional[NmapResult]: Scan results or None
        """
        if not self.is_available():
            log_error("Nmap not available")
            return None
        
        # Build command
        cmd = [self.path, target]
        
        # Add port specification
        if ports:
            port_str = ','.join(str(p) for p in ports)
            cmd.extend(['-p', port_str])
        
        # Add default args
        if self.default_args:
            cmd.extend(self.default_args.split())
        
        # Add custom args
        if args:
            cmd.extend(args.split())
        
        # Add output format (XML for parsing)
        cmd.extend(['-oX', '-'])
        
        log_info(f"🔍 Running Nmap scan on {target}")
        log_debug(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0 and result.stderr:
                log_warning(f"Nmap had issues: {result.stderr[:200]}")
            
            return self._parse_output(result.stdout, target)
            
        except subprocess.TimeoutExpired:
            log_error(f"Nmap scan timed out after {timeout}s")
            return None
        except Exception as e:
            log_error(f"Nmap scan failed: {e}")
            return None
    
    def scan_ports(self, target: str, ports: List[int]) -> Optional[NmapResult]:
        """Scan specific ports."""
        return self.scan(target, ports=ports)
    
    def scan_common_ports(self, target: str) -> Optional[NmapResult]:
        """Scan common ports (top 25)."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                        445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 
                        8080, 8443, 27017, 8080]
        return self.scan(target, ports=common_ports)
    
    def scan_all_ports(self, target: str) -> Optional[NmapResult]:
        """Scan all ports (1-65535)."""
        return self.scan(target, ports=None)
    
    def _parse_output(self, output: str, target: str) -> Optional[NmapResult]:
        """Parse Nmap XML output."""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(output)
            
            # Find host
            host = root.find('host')
            if host is None:
                log_warning("No host found in Nmap output")
                return self._parse_text_output(output, target)
            
            # Get host status
            status_elem = host.find('status')
            host_status = status_elem.get('state') if status_elem is not None else 'unknown'
            
            # Get hostname
            hostname_elem = host.find('hostnames/hostname')
            hostname = hostname_elem.get('name') if hostname_elem is not None else None
            
            # Get OS
            os_elem = host.find('os/osmatch')
            os_name = os_elem.get('name') if os_elem is not None else None
            
            # Get ports
            ports = []
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_id = int(port_elem.get('portid'))
                    protocol = port_elem.get('protocol')
                    
                    state_elem = port_elem.find('state')
                    state = state_elem.get('state') if state_elem is not None else 'unknown'
                    
                    service_elem = port_elem.find('service')
                    service = service_elem.get('name') if service_elem is not None else 'unknown'
                    version = service_elem.get('version') if service_elem is not None else ''
                    
                    if state == 'open':
                        ports.append({
                            'port': port_id,
                            'protocol': protocol,
                            'state': state,
                            'service': service,
                            'version': version
                        })
            
            # Get scripts
            scripts = []
            for script_elem in host.findall('.//script'):
                scripts.append({
                    'id': script_elem.get('id', ''),
                    'output': script_elem.get('output', '')
                })
            
            return NmapResult(
                target=target,
                status=host_status,
                hostname=hostname,
                os=os_name,
                ports=ports,
                scripts=scripts,
                raw_output=output
            )
            
        except Exception as e:
            log_debug(f"XML parsing failed: {e}, falling back to text parsing")
            return self._parse_text_output(output, target)
    
    def _parse_text_output(self, output: str, target: str) -> Optional[NmapResult]:
        """Parse Nmap text output (fallback)."""
        ports = []
        host_status = 'unknown'
        os_name = None
        hostname = None
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            if 'Host is up' in line:
                host_status = 'up'
            
            # Parse hostname
            if 'Nmap scan report for' in line:
                parts = line.replace('Nmap scan report for', '').strip()
                if '(' in parts and ')' in parts:
                    hostname = parts.split('(')[0].strip()
            
            # Parse ports
            port_match = re.search(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\w+)\s*(.*)', line)
            if port_match:
                port = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version = port_match.group(5).strip()
                
                if state == 'open':
                    ports.append({
                        'port': port,
                        'protocol': protocol,
                        'state': state,
                        'service': service,
                        'version': version
                    })
            
            # Parse OS
            os_match = re.search(r'OS details:\s*(.*)', line)
            if os_match:
                os_name = os_match.group(1).strip()
        
        return NmapResult(
            target=target,
            status=host_status,
            hostname=hostname,
            os=os_name,
            ports=ports,
            raw_output=output
        )
    
    def get_open_ports(self, target: str) -> List[int]:
        """Get list of open ports."""
        result = self.scan_common_ports(target)
        if result:
            return [p['port'] for p in result.ports]
        return []
    
    def get_services(self, target: str) -> Dict[int, str]:
        """Get service names for open ports."""
        result = self.scan_common_ports(target)
        if result:
            return {p['port']: p.get('service', 'unknown') for p in result.ports}
        return {}
    
    def get_results_as_dict(self, target: str) -> Dict[str, Any]:
        """Return scan results as a dictionary."""
        result = self.scan_common_ports(target)
        if not result:
            return {'error': 'Scan failed', 'target': target}
        
        return {
            'target': target,
            'status': result.status,
            'hostname': result.hostname,
            'os': result.os,
            'open_ports': [p['port'] for p in result.ports],
            'total_open': len(result.ports),
            'services': {p['port']: p.get('service', 'unknown') for p in result.ports},
            'scripts': result.scripts
        }