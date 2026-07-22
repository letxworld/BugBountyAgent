"""
BugBountyAgent - Knowledge Base
================================
This module provides persistent storage and retrieval for:
- Vulnerability patterns
- CVE data
- Attack chains
- Learned behaviors
- Past findings

Uses SQLite for structured data and JSON for pattern storage.
"""

import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

from app.core import get_config, log_info, log_warning, log_error, log_debug, get_timestamp

# ============================================================
# Data Classes
# ============================================================

@dataclass
class Finding:
    """Represents a vulnerability finding."""
    id: str
    target: str
    type: str
    severity: str  # critical, high, medium, low, info
    description: str
    reproduction_steps: str
    remediation: str
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    url: Optional[str] = None
    payload: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    timestamp: str = ""
    scan_id: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = get_timestamp()

@dataclass
class Pattern:
    """Represents a learned vulnerability pattern."""
    id: str
    name: str
    category: str  # injection, xss, auth, etc.
    detection_method: str  # regex, header, behavior, etc.
    indicators: List[str]  # Signatures that indicate this pattern
    payloads: List[str]
    confidence: float  # 0.0 - 1.0
    occurrences: int
    first_seen: str
    last_seen: str
    related_cves: List[str]

@dataclass
class AttackChain:
    """Represents a full attack chain."""
    id: str
    name: str
    target: str
    steps: List[Dict[str, Any]]
    findings: List[str]  # Finding IDs
    severity: str
    description: str
    completed: bool
    timestamp: str
    success_count: int
    failure_count: int

@dataclass
class TargetProfile:
    """Represents a target's profile."""
    id: str
    domain: str
    subdomains: List[str]
    ports: List[int]
    technologies: Dict[str, str]
    endpoints: List[str]
    findings: List[str]  # Finding IDs
    last_scan: str
    total_scans: int
    total_findings: int

# ============================================================
# Knowledge Base Class
# ============================================================

class KnowledgeBase:
    """
    Main knowledge base for storing and retrieving all data.
    
    Uses SQLite for structured data with JSON blobs for flexibility.
    """
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or get_config('database.sqlite.path', './data/bugbounty.db')
        self._ensure_db()
        self._cache = {}
        log_info(f"Knowledge Base initialized at: {self.db_path}")
    
    def _ensure_db(self):
        """Ensure the database exists with all required tables."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                target TEXT,
                type TEXT,
                severity TEXT,
                description TEXT,
                reproduction_steps TEXT,
                remediation TEXT,
                cvss_score REAL,
                cve_id TEXT,
                url TEXT,
                payload TEXT,
                request TEXT,
                response TEXT,
                timestamp TEXT,
                scan_id TEXT,
                raw_data TEXT
            )
        ''')
        
        # Patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS patterns (
                id TEXT PRIMARY KEY,
                name TEXT,
                category TEXT,
                detection_method TEXT,
                indicators TEXT,
                payloads TEXT,
                confidence REAL,
                occurrences INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                related_cves TEXT,
                raw_data TEXT
            )
        ''')
        
        # Attack chains table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chains (
                id TEXT PRIMARY KEY,
                name TEXT,
                target TEXT,
                steps TEXT,
                findings TEXT,
                severity TEXT,
                description TEXT,
                completed INTEGER,
                timestamp TEXT,
                success_count INTEGER,
                failure_count INTEGER,
                raw_data TEXT
            )
        ''')
        
        # Target profiles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                domain TEXT UNIQUE,
                subdomains TEXT,
                ports TEXT,
                technologies TEXT,
                endpoints TEXT,
                findings TEXT,
                last_scan TEXT,
                total_scans INTEGER,
                total_findings INTEGER,
                raw_data TEXT
            )
        ''')
        
        # CVEs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                cve_id TEXT UNIQUE,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                published TEXT,
                modified TEXT,
                references TEXT,
                raw_data TEXT
            )
        ''')
        
        # Indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_patterns_category ON patterns(category)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_chains_target ON chains(target)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id)')
        
        conn.commit()
        conn.close()
    
    def _get_connection(self):
        """Get a database connection."""
        return sqlite3.connect(self.db_path)
    
    def _json_dumps(self, obj):
        """Serialize object to JSON string."""
        return json.dumps(obj, default=str)
    
    def _json_loads(self, data):
        """Deserialize JSON string to object."""
        if not data:
            return {}
        try:
            return json.loads(data)
        except:
            return {}
    
    # ============================================================
    # Findings Methods
    # ============================================================
    
    def save_finding(self, finding: Finding) -> bool:
        """Save a finding to the knowledge base."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO findings 
                (id, target, type, severity, description, reproduction_steps, 
                 remediation, cvss_score, cve_id, url, payload, request, 
                 response, timestamp, scan_id, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                finding.id,
                finding.target,
                finding.type,
                finding.severity,
                finding.description,
                finding.reproduction_steps,
                finding.remediation,
                finding.cvss_score,
                finding.cve_id,
                finding.url,
                finding.payload,
                finding.request,
                finding.response,
                finding.timestamp,
                finding.scan_id,
                self._json_dumps(asdict(finding))
            ))
            
            conn.commit()
            conn.close()
            
            # Update target profile
            self._update_target_profile(finding.target, finding.id)
            
            log_debug(f"Saved finding: {finding.id} ({finding.severity}) - {finding.type}")
            return True
            
        except Exception as e:
            log_error(f"Failed to save finding: {e}")
            return False
    
    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Retrieve a finding by ID."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return Finding(
                    id=row[0],
                    target=row[1],
                    type=row[2],
                    severity=row[3],
                    description=row[4],
                    reproduction_steps=row[5],
                    remediation=row[6],
                    cvss_score=row[7],
                    cve_id=row[8],
                    url=row[9],
                    payload=row[10],
                    request=row[11],
                    response=row[12],
                    timestamp=row[13],
                    scan_id=row[14]
                )
            return None
            
        except Exception as e:
            log_error(f"Failed to get finding: {e}")
            return None
    
    def get_findings_by_target(self, target: str, limit: int = 100) -> List[Finding]:
        """Get all findings for a target."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM findings 
                WHERE target = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (target, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            findings = []
            for row in rows:
                findings.append(Finding(
                    id=row[0],
                    target=row[1],
                    type=row[2],
                    severity=row[3],
                    description=row[4],
                    reproduction_steps=row[5],
                    remediation=row[6],
                    cvss_score=row[7],
                    cve_id=row[8],
                    url=row[9],
                    payload=row[10],
                    request=row[11],
                    response=row[12],
                    timestamp=row[13],
                    scan_id=row[14]
                ))
            
            return findings
            
        except Exception as e:
            log_error(f"Failed to get findings: {e}")
            return []
    
    def get_findings_by_severity(self, severity: str, limit: int = 100) -> List[Finding]:
        """Get findings by severity level."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM findings 
                WHERE severity = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (severity, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            findings = []
            for row in rows:
                findings.append(Finding(
                    id=row[0],
                    target=row[1],
                    type=row[2],
                    severity=row[3],
                    description=row[4],
                    reproduction_steps=row[5],
                    remediation=row[6],
                    cvss_score=row[7],
                    cve_id=row[8],
                    url=row[9],
                    payload=row[10],
                    request=row[11],
                    response=row[12],
                    timestamp=row[13],
                    scan_id=row[14]
                ))
            
            return findings
            
        except Exception as e:
            log_error(f"Failed to get findings by severity: {e}")
            return []
    
    def get_all_findings(self, limit: int = 1000) -> List[Finding]:
        """Get all findings with limit."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM findings 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            findings = []
            for row in rows:
                findings.append(Finding(
                    id=row[0],
                    target=row[1],
                    type=row[2],
                    severity=row[3],
                    description=row[4],
                    reproduction_steps=row[5],
                    remediation=row[6],
                    cvss_score=row[7],
                    cve_id=row[8],
                    url=row[9],
                    payload=row[10],
                    request=row[11],
                    response=row[12],
                    timestamp=row[13],
                    scan_id=row[14]
                ))
            
            return findings
            
        except Exception as e:
            log_error(f"Failed to get all findings: {e}")
            return []
    
    # ============================================================
    # Pattern Methods
    # ============================================================
    
    def save_pattern(self, pattern: Pattern) -> bool:
        """Save or update a pattern."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO patterns 
                (id, name, category, detection_method, indicators, payloads,
                 confidence, occurrences, first_seen, last_seen, related_cves, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                pattern.id,
                pattern.name,
                pattern.category,
                pattern.detection_method,
                self._json_dumps(pattern.indicators),
                self._json_dumps(pattern.payloads),
                pattern.confidence,
                pattern.occurrences,
                pattern.first_seen,
                pattern.last_seen,
                self._json_dumps(pattern.related_cves),
                self._json_dumps(asdict(pattern))
            ))
            
            conn.commit()
            conn.close()
            
            log_debug(f"Saved pattern: {pattern.name} (confidence: {pattern.confidence})")
            return True
            
        except Exception as e:
            log_error(f"Failed to save pattern: {e}")
            return False
    
    def get_patterns_by_category(self, category: str) -> List[Pattern]:
        """Get patterns by category."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM patterns WHERE category = ? ORDER BY confidence DESC', (category,))
            rows = cursor.fetchall()
            conn.close()
            
            patterns = []
            for row in rows:
                patterns.append(Pattern(
                    id=row[0],
                    name=row[1],
                    category=row[2],
                    detection_method=row[3],
                    indicators=self._json_loads(row[4]),
                    payloads=self._json_loads(row[5]),
                    confidence=row[6],
                    occurrences=row[7],
                    first_seen=row[8],
                    last_seen=row[9],
                    related_cves=self._json_loads(row[10])
                ))
            
            return patterns
            
        except Exception as e:
            log_error(f"Failed to get patterns: {e}")
            return []
    
    # ============================================================
    # Chain Methods
    # ============================================================
    
    def save_chain(self, chain: AttackChain) -> bool:
        """Save an attack chain."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO chains 
                (id, name, target, steps, findings, severity, description,
                 completed, timestamp, success_count, failure_count, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                chain.id,
                chain.name,
                chain.target,
                self._json_dumps(chain.steps),
                self._json_dumps(chain.findings),
                chain.severity,
                chain.description,
                1 if chain.completed else 0,
                chain.timestamp,
                chain.success_count,
                chain.failure_count,
                self._json_dumps(asdict(chain))
            ))
            
            conn.commit()
            conn.close()
            
            log_info(f"Saved chain: {chain.name} (severity: {chain.severity})")
            return True
            
        except Exception as e:
            log_error(f"Failed to save chain: {e}")
            return False
    
    def get_chains_by_target(self, target: str) -> List[AttackChain]:
        """Get all chains for a target."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM chains WHERE target = ? ORDER BY timestamp DESC', (target,))
            rows = cursor.fetchall()
            conn.close()
            
            chains = []
            for row in rows:
                chains.append(AttackChain(
                    id=row[0],
                    name=row[1],
                    target=row[2],
                    steps=self._json_loads(row[3]),
                    findings=self._json_loads(row[4]),
                    severity=row[5],
                    description=row[6],
                    completed=bool(row[7]),
                    timestamp=row[8],
                    success_count=row[9],
                    failure_count=row[10]
                ))
            
            return chains
            
        except Exception as e:
            log_error(f"Failed to get chains: {e}")
            return []
    
    # ============================================================
    # Target Profile Methods
    # ============================================================
    
    def _update_target_profile(self, target: str, finding_id: str):
        """Update target profile with new finding."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Check if target exists
            cursor.execute('SELECT * FROM targets WHERE domain = ?', (target,))
            row = cursor.fetchone()
            
            if row:
                # Update existing target
                findings = self._json_loads(row[7])
                if finding_id not in findings:
                    findings.append(finding_id)
                
                cursor.execute('''
                    UPDATE targets SET 
                        findings = ?,
                        total_findings = total_findings + 1,
                        last_scan = ?
                    WHERE domain = ?
                ''', (
                    self._json_dumps(findings),
                    get_timestamp(),
                    target
                ))
            else:
                # Create new target profile
                cursor.execute('''
                    INSERT INTO targets 
                    (id, domain, subdomains, ports, technologies, endpoints, 
                     findings, last_scan, total_scans, total_findings)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    self._generate_id(),
                    target,
                    self._json_dumps([]),
                    self._json_dumps([]),
                    self._json_dumps({}),
                    self._json_dumps([]),
                    self._json_dumps([finding_id]),
                    get_timestamp(),
                    1,
                    1
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            log_error(f"Failed to update target profile: {e}")
    
    def get_target_profile(self, target: str) -> Optional[TargetProfile]:
        """Get target profile."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM targets WHERE domain = ?', (target,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return TargetProfile(
                    id=row[0],
                    domain=row[1],
                    subdomains=self._json_loads(row[2]),
                    ports=self._json_loads(row[3]),
                    technologies=self._json_loads(row[4]),
                    endpoints=self._json_loads(row[5]),
                    findings=self._json_loads(row[6]),
                    last_scan=row[7],
                    total_scans=row[8],
                    total_findings=row[9]
                )
            return None
            
        except Exception as e:
            log_error(f"Failed to get target profile: {e}")
            return None
    
    def update_target_subdomains(self, target: str, subdomains: List[str]):
        """Update target subdomains."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT subdomains FROM targets WHERE domain = ?', (target,))
            row = cursor.fetchone()
            
            if row:
                existing = self._json_loads(row[0])
                combined = list(set(existing + subdomains))
                cursor.execute('UPDATE targets SET subdomains = ? WHERE domain = ?', (self._json_dumps(combined), target))
                conn.commit()
            
            conn.close()
            
        except Exception as e:
            log_error(f"Failed to update subdomains: {e}")
    
    def _generate_id(self) -> str:
        """Generate a unique ID."""
        import random
        import string
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    
    # ============================================================
    # Statistics & Analytics
    # ============================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get knowledge base statistics."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            stats = {}
            
            # Finding stats
            cursor.execute('SELECT COUNT(*) FROM findings')
            stats['total_findings'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT severity, COUNT(*) FROM findings GROUP BY severity')
            stats['severity_counts'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            cursor.execute('SELECT target, COUNT(*) FROM findings GROUP BY target ORDER BY COUNT(*) DESC LIMIT 10')
            stats['top_targets'] = [(row[0], row[1]) for row in cursor.fetchall()]
            
            # Pattern stats
            cursor.execute('SELECT COUNT(*) FROM patterns')
            stats['total_patterns'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT category, COUNT(*) FROM patterns GROUP BY category')
            stats['pattern_categories'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Chain stats
            cursor.execute('SELECT COUNT(*) FROM chains')
            stats['total_chains'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT completed, COUNT(*) FROM chains GROUP BY completed')
            chain_counts = cursor.fetchall()
            stats['completed_chains'] = chain_counts[0][1] if chain_counts and chain_counts[0][0] == 1 else 0
            stats['incomplete_chains'] = chain_counts[0][1] if chain_counts and chain_counts[0][0] == 0 else 0
            
            conn.close()
            
            return stats
            
        except Exception as e:
            log_error(f"Failed to get statistics: {e}")
            return {}
    
    # ============================================================
    # Cleanup & Maintenance
    # ============================================================
    
    def cleanup_old_data(self, days: int = 90):
        """Clean up data older than specified days."""
        try:
            cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Delete old findings (but keep critical/high severity)
            cursor.execute('''
                DELETE FROM findings 
                WHERE timestamp < ? 
                AND severity NOT IN ('critical', 'high')
            ''', (cutoff,))
            
            # Delete old chains
            cursor.execute('DELETE FROM chains WHERE timestamp < ? AND completed = 0', (cutoff,))
            
            # Delete old patterns (low confidence)
            cursor.execute('DELETE FROM patterns WHERE confidence < 0.3 AND last_seen < ?', (cutoff,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            log_info(f"Cleaned up {deleted_count} old records")
            return deleted_count
            
        except Exception as e:
            log_error(f"Failed to cleanup data: {e}")
            return 0