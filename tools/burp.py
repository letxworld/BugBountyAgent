"""
BugBountyAgent - Burp Suite Professional Wrapper
==================================================
Wrapper for Burp Suite Professional integration via REST API.
"""

import os
import subprocess
import time
import requests
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

from core.config import Config
from core.utils import log_info, log_error, log_warning, log_debug


@dataclass
class BurpIssue:
    """Issue from Burp Suite scan."""
    name: str
    severity: str  # High, Medium, Low, Information
    description: str
    remediation: str
    url: str
    confidence: str  # Certain, Firm, Tentative
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []


class BurpWrapper:
    """
    Wrapper for Burp Suite Professional integration.
    Uses REST API for scanning and issue retrieval.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.tool_config = config.get('tools.burp', {})
        self.enabled = self.tool_config.get('enabled', False)
        self.path = self.tool_config.get('path', '/usr/local/bin/burpsuite')
        self.port = self.tool_config.get('port', 8080)
        self.api_key = self.tool_config.get('api_key', '')
        
        self._process = None
        self._available = None
    
    def is_available(self) -> bool:
        """Check if Burp Suite is installed."""
        if self._available is not None:
            return self._available
        
        if not self.enabled:
            self._available = False
            return False
        
        if os.path.exists(self.path):
            self._available = True
            log_info(f"✅ Burp Suite found at {self.path}")
        else:
            self._available = False
            log_warning(f"Burp Suite not found at {self.path}")
        
        return self._available
    
    def is_running(self) -> bool:
        """Check if Burp Suite is running."""
        if not self.enabled:
            return False
        
        try:
            # Check if API endpoint is accessible
            url = f"http://127.0.0.1:{self.port}/v0.1/"
            headers = {}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            response = requests.get(url, headers=headers, timeout=3)
            return response.status_code == 200
            
        except requests.RequestException:
            return False
    
    def start(self) -> bool:
        """Start Burp Suite in background."""
        if not self.enabled:
            log_warning("Burp Suite is disabled in config")
            return False
        
        if not self.is_available():
            log_error("Burp Suite not installed")
            return False
        
        if self.is_running():
            log_info("Burp Suite is already running")
            return True
        
        try:
            # Start Burp with REST API enabled
            cmd = [
                self.path,
                '--rest-api-port', str(self.port),
                '--rest-api-login', 'admin',
                '--rest-api-password', 'admin'
            ]
            
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False
            )
            
            # Wait for it to be ready
            for attempt in range(30):
                time.sleep(1)
                if self.is_running():
                    log_info(f"✅ Burp Suite started (PID: {self._process.pid})")
                    return True
            
            log_warning("Burp Suite started but may not be ready")
            return True
            
        except Exception as e:
            log_error(f"Failed to start Burp Suite: {e}")
            return False
    
    def stop(self) -> bool:
        """Stop Burp Suite."""
        if self._process:
            try:
                self._process.terminate()
                self._process = None
                log_info("✅ Burp Suite stopped")
                return True
            except Exception as e:
                log_error(f"Failed to stop Burp: {e}")
                return False
        
        return False
    
    def _make_request(self, endpoint: str, method: str = 'GET',
                      data: Dict = None) -> Optional[Dict]:
        """Make a request to the Burp REST API."""
        if not self.is_running():
            log_warning("Burp Suite is not running")
            return None
        
        url = f"http://127.0.0.1:{self.port}{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        
        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code in [200, 201, 202]:
                return response.json() if response.content else {}
            else:
                log_error(f"Burp API error: {response.status_code}")
                return None
                
        except requests.RequestException as e:
            log_error(f"Burp API request failed: {e}")
            return None
    
    def scan(self, url: str) -> Optional[str]:
        """
        Start a scan on a URL using Burp Suite.
        
        Args:
            url: Target URL
            
        Returns:
            Optional[str]: Scan ID or None
        """
        if not self.enabled:
            log_warning("Burp Suite is disabled")
            return None
        
        if not self.is_running():
            if not self.start():
                return None
        
        log_info(f"🔍 Starting Burp scan on: {url}")
        
        data = {'url': url}
        result = self._make_request('/v0.1/scan', 'POST', data)
        
        if result and 'task_id' in result:
            scan_id = result['task_id']
            log_info(f"✅ Burp scan started: {scan_id}")
            return scan_id
        
        return None
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get status of a Burp scan."""
        result = self._make_request(f'/v0.1/scan/{scan_id}')
        
        if result:
            return {
                'id': scan_id,
                'status': result.get('status', 'unknown'),
                'progress': result.get('progress', 0),
                'issues_found': result.get('issues_found', 0)
            }
        
        return None
    
    def get_issues(self, scan_id: Optional[str] = None) -> List[BurpIssue]:
        """
        Get issues from Burp Suite.
        
        Args:
            scan_id: Specific scan ID (optional)
            
        Returns:
            List[BurpIssue]: List of issues
        """
        if not self.enabled or not self.is_running():
            return []
        
        endpoint = '/v0.1/issues'
        if scan_id:
            endpoint += f'?scan_id={scan_id}'
        
        result = self._make_request(endpoint)
        
        if not result or 'issues' not in result:
            return []
        
        issues = []
        for item in result['issues']:
            issues.append(BurpIssue(
                name=item.get('name', 'Unknown'),
                severity=item.get('severity', 'Medium'),
                description=item.get('description', ''),
                remediation=item.get('remediation', ''),
                url=item.get('url', ''),
                confidence=item.get('confidence', 'Tentative'),
                cve_id=item.get('cve_id', ''),
                cvss_score=item.get('cvss_score', None),
                references=item.get('references', [])
            ))
        
        log_info(f"✅ Retrieved {len(issues)} issues from Burp")
        return issues
    
    def export_issues(self, output_path: str) -> bool:
        """
        Export issues to a file.
        
        Args:
            output_path: Path to save issues
            
        Returns:
            bool: Success status
        """
        issues = self.get_issues()
        if not issues:
            log_warning("No issues found to export")
            return False
        
        try:
            import json
            with open(output_path, 'w') as f:
                json.dump([{
                    'name': i.name,
                    'severity': i.severity,
                    'description': i.description,
                    'remediation': i.remediation,
                    'url': i.url,
                    'confidence': i.confidence,
                    'cve_id': i.cve_id,
                    'cvss_score': i.cvss_score,
                    'references': i.references
                } for i in issues], f, indent=2, default=str)
            
            log_info(f"✅ Exported {len(issues)} issues to {output_path}")
            return True
            
        except Exception as e:
            log_error(f"Failed to export issues: {e}")
            return False
    
    def get_results_as_dict(self, url: str) -> Dict[str, Any]:
        """Return scan results as a dictionary."""
        scan_id = self.scan(url)
        if not scan_id:
            return {'error': 'Failed to start scan'}
        
        # Wait for scan to complete (polling)
        for attempt in range(30):
            time.sleep(2)
            status = self.get_scan_status(scan_id)
            if status and status.get('status') == 'completed':
                break
        
        issues = self.get_issues(scan_id)
        
        severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Information': 0}
        for i in issues:
            severity_counts[i.severity] = severity_counts.get(i.severity, 0) + 1
        
        return {
            'target': url,
            'scan_id': scan_id,
            'total_issues': len(issues),
            'severity_counts': severity_counts,
            'issues': [
                {
                    'name': i.name,
                    'severity': i.severity,
                    'description': i.description[:200],
                    'remediation': i.remediation[:200],
                    'url': i.url,
                    'confidence': i.confidence,
                    'cve_id': i.cve_id,
                    'cvss_score': i.cvss_score
                }
                for i in issues
            ]
        }