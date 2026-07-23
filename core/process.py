"""
BugBountyAgent - Process Controller
=====================================
Manages system processes.
"""

import os
import signal
import subprocess
from typing import Optional, Dict, Any, List
from datetime import datetime

from .config import Config
from .utils import get_timestamp


class ProcessController:
    """Manages system processes."""
    
    def __init__(self, config: Config):
        self.config = config
        self.processes: Dict[str, subprocess.Popen] = {}
        self.psutil_available = False
        
        try:
            import psutil
            self.psutil_available = True
        except ImportError:
            pass
        
        print("🔄 ProcessController initialized")
    
    def start(self, command: str, name: Optional[str] = None, 
              env: Optional[Dict] = None) -> Optional[subprocess.Popen]:
        """Start a process."""
        try:
            full_env = os.environ.copy()
            if env:
                full_env.update(env)
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=full_env
            )
            
            process_name = name or command[:50]
            self.processes[process_name] = process
            return process
            
        except Exception as e:
            print(f"Failed to start process: {e}")
            return None
    
    def stop(self, process_name: str, force: bool = False) -> bool:
        """Stop a process."""
        if process_name not in self.processes:
            return False
        
        try:
            process = self.processes[process_name]
            if force:
                process.kill()
            else:
                process.terminate()
            
            del self.processes[process_name]
            return True
            
        except Exception as e:
            print(f"Failed to stop process: {e}")
            return False
    
    def stop_all(self) -> int:
        """Stop all managed processes."""
        count = 0
        for name in list(self.processes.keys()):
            if self.stop(name):
                count += 1
        return count
    
    def is_running(self, process_name: str) -> bool:
        """Check if a process is running."""
        if process_name not in self.processes:
            return False
        
        try:
            process = self.processes[process_name]
            return process.poll() is None
        except:
            return False
    
    def get_processes(self) -> List[Dict[str, Any]]:
        """Get information about managed processes."""
        processes = []
        for name, process in self.processes.items():
            processes.append({
                'name': name,
                'pid': process.pid,
                'running': process.poll() is None
            })
        return processes
    
    def kill_by_pid(self, pid: int, force: bool = False) -> bool:
        """Kill a process by PID."""
        try:
            if force:
                os.kill(pid, signal.SIGKILL)
            else:
                os.kill(pid, signal.SIGTERM)
            return True
        except Exception as e:
            print(f"Failed to kill PID {pid}: {e}")
            return False
    
    def get_system_processes(self) -> List[Dict[str, Any]]:
        """Get all system processes (requires psutil)."""
        if not self.psutil_available:
            return []
        
        try:
            import psutil
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except:
                    pass
            return processes
        except Exception as e:
            print(f"Failed to get system processes: {e}")
            return []