"""
BugBountyAgent - Database Operations
======================================
SQLite database operations, models, and CRUD for persistence.
"""

import sqlite3
import json
import os
from typing import Dict, Any, List, Optional

from .config import Config
from .utils import get_timestamp, generate_id


class Database:
    """
    SQLite database manager for all persistent storage.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.db_path = config.get('database.path', './data/state.db')
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_tables()
        print(f"🗄️ Database initialized at: {self.db_path}")
    
    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)
    
    def _init_tables(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                url TEXT UNIQUE,
                status TEXT,
                added TEXT,
                completed_at TEXT,
                raw_data TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                target_id TEXT,
                title TEXT,
                severity TEXT,
                type TEXT,
                description TEXT,
                reproduction_steps TEXT,
                remediation TEXT,
                cve_id TEXT,
                cvss_score REAL,
                url TEXT,
                source TEXT,
                timestamp TEXT,
                raw_data TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chains (
                id TEXT PRIMARY KEY,
                target_id TEXT,
                name TEXT,
                severity TEXT,
                steps TEXT,
                completed INTEGER,
                timestamp TEXT,
                raw_data TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_id TEXT,
                scan_type TEXT,
                status TEXT,
                start_time TEXT,
                end_time TEXT,
                findings_count INTEGER,
                raw_data TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    # ============================================================
    # Target Operations
    # ============================================================
    
    def save_target(self, target: Dict[str, Any]) -> bool:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO targets 
                (id, url, status, added, completed_at, raw_data)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                target.get('id'),
                target.get('url'),
                target.get('status', 'pending'),
                target.get('added', get_timestamp()),
                target.get('completed_at'),
                json.dumps(target, default=str)
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Database error: {e}")
            return False
        finally:
            conn.close()
    
    def get_target(self, target_id: str) -> Optional[Dict]:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT raw_data FROM targets WHERE id = ?', (target_id,))
            row = cursor.fetchone()
            return json.loads(row[0]) if row else None
        except Exception as e:
            print(f"❌ Database error: {e}")
            return None
        finally:
            conn.close()
    
    def get_all_targets(self) -> List[Dict]:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT raw_data FROM targets ORDER BY added DESC')
            return [json.loads(row[0]) for row in cursor.fetchall()]
        except Exception as e:
            print(f"❌ Database error: {e}")
            return []
        finally:
            conn.close()
    
    def delete_target(self, target_id: str) -> bool:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM targets WHERE id = ?', (target_id,))
            cursor.execute('DELETE FROM findings WHERE target_id = ?', (target_id,))
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Database error: {e}")
            return False
        finally:
            conn.close()
    
    # ============================================================
    # Finding Operations
    # ============================================================
    
    def save_finding(self, finding: Dict[str, Any]) -> bool:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO findings 
                (id, target_id, title, severity, type, description,
                 reproduction_steps, remediation, cve_id, cvss_score,
                 url, source, timestamp, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                finding.get('id', generate_id()),
                finding.get('target_id'),
                finding.get('title', 'Unknown'),
                finding.get('severity', 'info'),
                finding.get('type', 'unknown'),
                finding.get('description', ''),
                finding.get('reproduction_steps', ''),
                finding.get('remediation', ''),
                finding.get('cve_id', ''),
                finding.get('cvss_score', 0.0),
                finding.get('url', ''),
                finding.get('source', 'unknown'),
                finding.get('timestamp', get_timestamp()),
                json.dumps(finding, default=str)
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Database error: {e}")
            return False
        finally:
            conn.close()
    
    def get_findings_by_target(self, target_id: str) -> List[Dict]:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT raw_data FROM findings WHERE target_id = ? ORDER BY timestamp DESC', (target_id,))
            return [json.loads(row[0]) for row in cursor.fetchall()]
        except Exception as e:
            print(f"❌ Database error: {e}")
            return []
        finally:
            conn.close()
    
    def get_all_findings(self) -> List[Dict]:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT raw_data FROM findings ORDER BY timestamp DESC')
            return [json.loads(row[0]) for row in cursor.fetchall()]
        except Exception as e:
            print(f"❌ Database error: {e}")
            return []
        finally:
            conn.close()
    
    def delete_finding(self, finding_id: str) -> bool:
        """Delete a finding by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM findings WHERE id = ?', (finding_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"❌ Database error deleting finding: {e}")
            return False
        finally:
            conn.close()
    
    def clear_findings(self) -> bool:
        """Clear all findings."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM findings')
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Database error clearing findings: {e}")
            return False
        finally:
            conn.close()
    
    # ============================================================
    # Chain Operations
    # ============================================================
    
    def save_chain(self, chain: Dict[str, Any]) -> bool:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO chains 
                (id, target_id, name, severity, steps, completed, timestamp, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                chain.get('id', generate_id()),
                chain.get('target_id'),
                chain.get('name', 'Unknown Chain'),
                chain.get('severity', 'medium'),
                json.dumps(chain.get('steps', []), default=str),
                1 if chain.get('completed', False) else 0,
                chain.get('timestamp', get_timestamp()),
                json.dumps(chain, default=str)
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Database error: {e}")
            return False
        finally:
            conn.close()
    
    def get_chains_by_target(self, target_id: str) -> List[Dict]:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT raw_data FROM chains WHERE target_id = ? ORDER BY timestamp DESC', (target_id,))
            return [json.loads(row[0]) for row in cursor.fetchall()]
        except Exception as e:
            print(f"❌ Database error: {e}")
            return []
        finally:
            conn.close()
    
    def get_all_chains(self) -> List[Dict]:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT raw_data FROM chains ORDER BY timestamp DESC')
            return [json.loads(row[0]) for row in cursor.fetchall()]
        except Exception as e:
            print(f"❌ Database error: {e}")
            return []
        finally:
            conn.close()
    
    # ============================================================
    # Scan Operations
    # ============================================================
    
    def save_scan(self, scan: Dict[str, Any]) -> bool:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO scans 
                (id, target_id, scan_type, status, start_time, end_time, findings_count, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan.get('id', generate_id()),
                scan.get('target_id'),
                scan.get('scan_type', 'full'),
                scan.get('status', 'running'),
                scan.get('start_time', get_timestamp()),
                scan.get('end_time'),
                scan.get('findings_count', 0),
                json.dumps(scan, default=str)
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Database error: {e}")
            return False
        finally:
            conn.close()
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT raw_data FROM scans WHERE id = ?', (scan_id,))
            row = cursor.fetchone()
            return json.loads(row[0]) if row else None
        except Exception as e:
            print(f"❌ Database error: {e}")
            return None
        finally:
            conn.close()
    
    def get_scans_by_target(self, target_id: str) -> List[Dict]:
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT raw_data FROM scans WHERE target_id = ? ORDER BY start_time DESC', (target_id,))
            return [json.loads(row[0]) for row in cursor.fetchall()]
        except Exception as e:
            print(f"❌ Database error: {e}")
            return []
        finally:
            conn.close()
    
    # ============================================================
    # Statistics
    # ============================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        conn = self._get_connection()
        cursor = conn.cursor()
        stats = {}
        try:
            cursor.execute('SELECT COUNT(*) FROM targets')
            stats['targets'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM findings')
            stats['findings'] = cursor.fetchone()[0]
            cursor.execute('SELECT severity, COUNT(*) FROM findings GROUP BY severity')
            stats['severity_counts'] = {row[0]: row[1] for row in cursor.fetchall()}
            cursor.execute('SELECT COUNT(*) FROM chains')
            stats['chains'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM scans')
            stats['scans'] = cursor.fetchone()[0]
        except Exception as e:
            print(f"❌ Database error: {e}")
        finally:
            conn.close()
        return stats
