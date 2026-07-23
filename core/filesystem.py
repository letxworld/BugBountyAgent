"""
BugBountyAgent - File System Controller
========================================
Controls file system operations.
"""

import os
import json
import shutil
import time
import glob
import fnmatch
from typing import List, Dict, Any, Optional, Union
from datetime import datetime

from .config import Config
from .utils import get_timestamp
from .logging import log_info, log_warning, log_error, log_debug


class FileSystemController:
    """
    Controls file system operations.
    """
    
    def __init__(self, config: Config):
        self.config = config
        
        # Directories
        self.data_dir = config.get('system.data_dir', './data')
        self.logs_dir = config.get('system.logs_dir', './logs')
        self.reports_dir = config.get('system.reports_dir', './data/reports')
        self.findings_dir = config.get('system.findings_dir', './data/findings')
        self.chains_dir = config.get('system.chains_dir', './data/chains')
        self.patterns_dir = config.get('system.patterns_dir', './data/patterns')
        self.screenshots_dir = config.get('system.screenshots_dir', './data/screenshots')
        self.tool_outputs_dir = config.get('system.tool_outputs_dir', './data/tool_outputs')
        self.temp_dir = config.get('system.temp_dir', './data/temp')
        
        # Retention settings
        self.retention_days = {
            'logs': config.get('storage.retention.logs', 30),
            'reports': config.get('storage.retention.reports', 60),
            'screenshots': config.get('storage.retention.screenshots', 30),
            'findings': config.get('storage.retention.findings', 365),
            'chains': config.get('storage.retention.chains', 180),
            'patterns': config.get('storage.retention.patterns', 180),
            'tool_outputs': config.get('storage.retention.tool_outputs', 30),
        }
        
        self.max_total_gb = config.get('storage.max_total_gb', 50)
        
        # Create directories
        self._ensure_dirs()
        log_info("📁 FileSystemController initialized")
    
    def _ensure_dirs(self):
        """Ensure all required directories exist."""
        for dir_path in [
            self.data_dir,
            self.logs_dir,
            self.reports_dir,
            self.findings_dir,
            self.chains_dir,
            self.patterns_dir,
            self.screenshots_dir,
            self.tool_outputs_dir,
            self.temp_dir
        ]:
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
    
    def create_directory(self, path: str) -> bool:
        """Create a directory."""
        try:
            os.makedirs(path, exist_ok=True)
            log_debug(f"📁 Created directory: {path}")
            return True
        except Exception as e:
            log_error(f"Failed to create directory: {e}")
            return False
    
    def directory_exists(self, path: str) -> bool:
        return os.path.isdir(path)
    
    def list_directories(self, path: str) -> List[str]:
        try:
            return [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]
        except Exception as e:
            log_error(f"Failed to list directories: {e}")
            return []
    
    def delete_directory(self, path: str) -> bool:
        try:
            shutil.rmtree(path)
            log_debug(f"🗑️ Deleted directory: {path}")
            return True
        except Exception as e:
            log_error(f"Failed to delete directory: {e}")
            return False
    
    def read_file(self, path: str) -> Optional[str]:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            log_error(f"Failed to read file {path}: {e}")
            return None
    
    def read_binary(self, path: str) -> Optional[bytes]:
        try:
            with open(path, 'rb') as f:
                return f.read()
        except Exception as e:
            log_error(f"Failed to read binary file {path}: {e}")
            return None
    
    def read_json(self, path: str) -> Optional[Dict]:
        content = self.read_file(path)
        if content:
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                log_error(f"Failed to parse JSON from {path}: {e}")
        return None
    
    def write_file(self, path: str, content: str) -> bool:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            log_debug(f"✍️ Wrote file: {path}")
            return True
        except Exception as e:
            log_error(f"Failed to write file {path}: {e}")
            return False
    
    def write_binary(self, path: str, content: bytes) -> bool:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as f:
                f.write(content)
            log_debug(f"✍️ Wrote binary file: {path}")
            return True
        except Exception as e:
            log_error(f"Failed to write binary file {path}: {e}")
            return False
    
    def write_json(self, path: str, data: Dict) -> bool:
        try:
            content = json.dumps(data, indent=2, default=str)
            return self.write_file(path, content)
        except Exception as e:
            log_error(f"Failed to write JSON to {path}: {e}")
            return False
    
    def append_file(self, path: str, content: str) -> bool:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'a', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            log_error(f"Failed to append to file {path}: {e}")
            return False
    
    def file_exists(self, path: str) -> bool:
        return os.path.isfile(path)
    
    def list_files(self, path: str, pattern: str = '*') -> List[str]:
        try:
            full_pattern = os.path.join(path, pattern)
            return [f for f in glob.glob(full_pattern) if os.path.isfile(f)]
        except Exception as e:
            log_error(f"Failed to list files in {path}: {e}")
            return []
    
    def delete_file(self, path: str) -> bool:
        try:
            os.remove(path)
            log_debug(f"🗑️ Deleted file: {path}")
            return True
        except Exception as e:
            log_error(f"Failed to delete file {path}: {e}")
            return False
    
    def move_file(self, source: str, dest: str) -> bool:
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.move(source, dest)
            log_debug(f"📦 Moved: {source} → {dest}")
            return True
        except Exception as e:
            log_error(f"Failed to move file {source} to {dest}: {e}")
            return False
    
    def get_size(self, path: str) -> int:
        try:
            if os.path.isfile(path):
                return os.path.getsize(path)
            elif os.path.isdir(path):
                total = 0
                for root, dirs, files in os.walk(path):
                    for f in files:
                        fp = os.path.join(root, f)
                        try:
                            total += os.path.getsize(fp)
                        except:
                            pass
                return total
            return 0
        except Exception as e:
            log_error(f"Failed to get size of {path}: {e}")
            return 0
    
    def _human_size(self, size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    def save_finding(self, target_id: str, finding: Dict) -> str:
        timestamp = get_timestamp()
        filename = f"{target_id}_{timestamp}.json"
        path = os.path.join(self.findings_dir, filename)
        self.write_json(path, finding)
        log_debug(f"🔍 Saved finding: {path}")
        return path
    
    def load_findings(self, target_id: str) -> List[Dict]:
        findings = []
        pattern = f"{target_id}_*.json"
        files = self.list_files(self.findings_dir, pattern)
        for file in files:
            data = self.read_json(file)
            if data:
                findings.append(data)
        return findings
    
    def save_report(self, target_id: str, content: Union[str, Dict]) -> str:
        timestamp = get_timestamp()
        path = os.path.join(self.reports_dir, f"{target_id}_{timestamp}.json")
        
        if isinstance(content, dict):
            self.write_json(path, content)
        else:
            self.write_file(path, content)
        
        log_info(f"📄 Report saved: {path}")
        return path
    
    def save_chain(self, target_id: str, chain: Dict) -> str:
        timestamp = get_timestamp()
        filename = f"{target_id}_{timestamp}_chain.json"
        path = os.path.join(self.chains_dir, filename)
        self.write_json(path, chain)
        log_debug(f"🔗 Saved chain: {path}")
        return path
    
    def save_pattern(self, pattern: Dict) -> str:
        timestamp = get_timestamp()
        filename = f"{pattern.get('id', 'unknown')}_{timestamp}.json"
        path = os.path.join(self.patterns_dir, filename)
        self.write_json(path, pattern)
        log_debug(f"🧠 Saved pattern: {path}")
        return path
    
    def load_patterns(self) -> List[Dict]:
        patterns = []
        files = self.list_files(self.patterns_dir, '*.json')
        for file in files:
            data = self.read_json(file)
            if data:
                patterns.append(data)
        return patterns
    
    def get_storage_usage(self) -> Dict[str, Any]:
        usage = {
            'database': 0,
            'reports': 0,
            'findings': 0,
            'chains': 0,
            'patterns': 0,
            'screenshots': 0,
            'logs': 0,
            'tool_outputs': 0,
            'temp': 0,
            'total': 0
        }
        
        db_path = self.config.get('database.path', './data/state.db')
        if self.file_exists(db_path):
            usage['database'] = self.get_size(db_path)
        
        usage['reports'] = self.get_size(self.reports_dir)
        usage['findings'] = self.get_size(self.findings_dir)
        usage['chains'] = self.get_size(self.chains_dir)
        usage['patterns'] = self.get_size(self.patterns_dir)
        usage['screenshots'] = self.get_size(self.screenshots_dir)
        usage['logs'] = self.get_size(self.logs_dir)
        usage['tool_outputs'] = self.get_size(self.tool_outputs_dir)
        usage['temp'] = self.get_size(self.temp_dir)
        
        usage['total'] = sum(usage.values())
        usage['total_gb'] = usage['total'] / (1024**3)
        usage['total_human'] = self._human_size(usage['total'])
        usage['max_gb'] = self.max_total_gb
        
        return usage
    
    def cleanup_old_files(self, days: int = 30) -> Dict[str, int]:
        cleaned = {
            'logs': 0, 'reports': 0, 'screenshots': 0,
            'tool_outputs': 0, 'temp': 0, 'findings': 0,
            'chains': 0, 'patterns': 0
        }
        
        cutoff = time.time() - (days * 24 * 60 * 60)
        
        for dir_name, dir_path in [
            ('logs', self.logs_dir),
            ('reports', self.reports_dir),
            ('screenshots', self.screenshots_dir),
            ('tool_outputs', self.tool_outputs_dir),
            ('temp', self.temp_dir),
            ('findings', self.findings_dir),
            ('chains', self.chains_dir),
            ('patterns', self.patterns_dir)
        ]:
            for file in self.list_files(dir_path, '*'):
                try:
                    if os.path.getmtime(file) < cutoff:
                        if self.delete_file(file):
                            cleaned[dir_name] += 1
                except:
                    pass
        
        total = sum(cleaned.values())
        if total > 0:
            log_info(f"🧹 Cleaned up {total} files older than {days} days")
        
        return cleaned
