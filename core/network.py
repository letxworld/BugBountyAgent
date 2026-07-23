"""
BugBountyAgent - Network Utilities
====================================
Network utilities for DNS, ports, HTTP, and connectivity.
"""

import socket
import subprocess
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

import requests
import dns.resolver

from .config import Config
from .logging import log_info, log_error, log_warning, log_debug


class NetworkUtils:
    """
    Network utilities for DNS, ports, HTTP, and connectivity.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get('network.timeout', 10)
    
    # ============================================================
    # DNS Utilities
    # ============================================================
    
    def resolve_dns(self, domain: str, record_type: str = 'A') -> List[str]:
        """Resolve DNS records for a domain."""
        try:
            answers = dns.resolver.resolve(domain, record_type)
            return [str(r) for r in answers]
        except Exception as e:
            log_debug(f"DNS resolution failed for {domain}: {e}")
            return []
    
    def reverse_dns(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup for an IP."""
        try:
            import dns.reversename
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, 'PTR')
            return str(answers[0])
        except Exception as e:
            log_debug(f"Reverse DNS failed for {ip}: {e}")
            return None
    
    def get_nameservers(self, domain: str) -> List[str]:
        """Get nameservers for a domain."""
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            return [str(r.target).rstrip('.') for r in answers]
        except:
            return []
    
    def get_mx_records(self, domain: str) -> List[Tuple[str, int]]:
        """Get MX records for a domain."""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            return [(str(r.exchange).rstrip('.'), r.preference) for r in answers]
        except:
            return []
    
    # ============================================================
    # Port Utilities
    # ============================================================
    
    def check_port(self, host: str, port: int, timeout: int = 3) -> bool:
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_ports(self, host: str, ports: List[int] = None) -> List[int]:
        """Scan ports on a host."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                    445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        
        open_ports = []
        for port in ports:
            if self.check_port(host, port):
                open_ports.append(port)
        return open_ports
    
    # ============================================================
    # HTTP Utilities
    # ============================================================
    
    def check_http(self, url: str) -> Dict[str, Any]:
        """Check HTTP connectivity."""
        try:
            response = requests.get(url, timeout=self.timeout, verify=False)
            return {
                'status': response.status_code,
                'success': response.status_code < 400,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds()
            }
        except Exception as e:
            return {
                'status': 0,
                'success': False,
                'error': str(e)
            }
    
    def get_headers(self, url: str) -> Optional[Dict[str, str]]:
        """Get HTTP headers."""
        try:
            response = requests.head(url, timeout=self.timeout, allow_redirects=True)
            return dict(response.headers)
        except:
            try:
                response = requests.get(url, timeout=self.timeout, stream=True)
                return dict(response.headers)
            except:
                return None
    
    def get_ssl_info(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Get SSL certificate information."""
        import ssl
        info = {'valid': False}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    info['valid'] = True
                    info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    info['not_before'] = cert.get('notBefore', '')
                    info['not_after'] = cert.get('notAfter', '')
                    info['cipher'] = ssock.cipher()
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    # ============================================================
    # System Utilities
    # ============================================================
    
    def ping(self, host: str, count: int = 4) -> Dict[str, Any]:
        """Ping a host."""
        try:
            cmd = ['ping', '-c', str(count), '-W', '2', host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_public_ip(self) -> Optional[str]:
        """Get public IP address."""
        services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ifconfig.me/ip'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    return ip
            except:
                continue
        
        return None
    
    def get_local_ip(self) -> Optional[str]:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return None