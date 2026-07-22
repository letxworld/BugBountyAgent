"""
BugBountyAgent - System Controller
===================================
This module provides system-level access:
- Running commands and tools
- Managing processes
- File system operations
- Burp Suite Professional integration
- Tool installation and management
"""

import os
import sys
import subprocess
import signal
import time
import json
import shutil
from typing import Optional, Dict, Any, List, Tuple, Union
from pathlib import Path
from datetime import datetime
import psutil

from app.core import get_config, log_info, log_warning, log_error, log_debug, get_timestamp, safe_filename

# ============================================================
# System Controller Class
# ============================================================

class SystemController:
    """
    Controls system-level operations including:
    - Running commands and tools
    - Managing processes
    - File operations
    - Burp Suite Professional integration
    - Tool installation
    """
    
    def __init__(self):
        self.working_dir = os.getcwd()
        self.temp_dir = get_config('system.temp_dir', '/tmp/bugbounty')
        self.whitelist = get_config('system.command_whitelist', [])
        self.blacklist = get_config('system.command_blacklist', [])
        
        # Burp Suite settings
        self.burp_config = {
            'enabled': get_config('tools.burp.enabled', False),
            'path': get_config('tools.burp.path', '/usr/local/bin/burpsuite'),
            'api_port': get_config('tools.burp.api_port', 8080),
            'api_key': get_config('tools.burp.api_key', None)
        }
        
        # Running processes
        self.running_processes = {}
        
        # Create temp directory
        os.makedirs(self.temp_dir, exist_ok=True)
        log_info("System Controller initialized")
    
    # ============================================================
    # Command Execution
    # ============================================================
    
    def run_command(self, command: Union[str, List[str]], 
                   timeout: int = 60,
                   capture_output: bool = True,
                   shell: bool = False,
                   env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Run a system command.
        
        Args:
            command: Command to run (string or list)
            timeout: Timeout in seconds
            capture_output: Capture stdout/stderr
            shell: Run in shell mode
            env: Environment variables
            
        Returns:
            Dict: {success, stdout, stderr, returncode, command}
        """
        # Security checks
        if not self._is_command_allowed(command):
            log_warning(f"Command blocked by security policy: {command}")
            return {
                'success': False,
                'stdout': '',
                'stderr': 'Command blocked by security policy',
                'returncode': -1,
                'command': str(command)
            }
        
        try:
            log_info(f"Running command: {command}")
            
            # Prepare environment
            full_env = os.environ.copy()
            if env:
                full_env.update(env)
            
            # Run command
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=capture_output,
                timeout=timeout,
                env=full_env,
                cwd=self.working_dir
            )
            
            stdout = result.stdout.decode('utf-8', errors='ignore') if result.stdout else ''
            stderr = result.stderr.decode('utf-8', errors='ignore') if result.stderr else ''
            
            success = result.returncode == 0
            
            if success:
                log_debug(f"Command succeeded: {command}")
            else:
                log_warning(f"Command failed (code {result.returncode}): {command}")
                if stderr:
                    log_debug(f"Stderr: {stderr[:200]}...")
            
            return {
                'success': success,
                'stdout': stdout,
                'stderr': stderr,
                'returncode': result.returncode,
                'command': str(command)
            }
            
        except subprocess.TimeoutExpired:
            log_error(f"Command timed out: {command}")
            return {
                'success': False,
                'stdout': '',
                'stderr': f'Command timed out after {timeout}s',
                'returncode': -1,
                'command': str(command)
            }
        except Exception as e:
            log_error(f"Command execution failed: {e}")
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'returncode': -1,
                'command': str(command)
            }
    
    def run_command_async(self, command: Union[str, List[str]], 
                         name: str = None,
                         env: Optional[Dict[str, str]] = None) -> Optional[subprocess.Popen]:
        """
        Run a command asynchronously (non-blocking).
        
        Args:
            command: Command to run
            name: Process name for tracking
            env: Environment variables
            
        Returns:
            Optional[subprocess.Popen]: Process object
        """
        if not self._is_command_allowed(command):
            log_warning(f"Command blocked by security policy: {command}")
            return None
        
        try:
            log_info(f"Starting async process: {command}")
            
            full_env = os.environ.copy()
            if env:
                full_env.update(env)
            
            process = subprocess.Popen(
                command,
                shell=isinstance(command, str),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=full_env,
                cwd=self.working_dir
            )
            
            process_name = name or str(command)
            self.running_processes[process_name] = process
            
            log_debug(f"Async process started: {process.pid}")
            return process
            
        except Exception as e:
            log_error(f"Async process failed: {e}")
            return None
    
    def kill_process(self, pid: int, force: bool = False) -> bool:
        """
        Kill a running process.
        
        Args:
            pid: Process ID
            force: Force kill (SIGKILL vs SIGTERM)
            
        Returns:
            bool: Success status
        """
        try:
            if force:
                os.kill(pid, signal.SIGKILL)
            else:
                os.kill(pid, signal.SIGTERM)
            log_debug(f"Killed process: {pid}")
            return True
        except Exception as e:
            log_error(f"Failed to kill process {pid}: {e}")
            return False
    
    def get_process_info(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get information about a running process."""
        try:
            process = psutil.Process(pid)
            return {
                'pid': pid,
                'name': process.name(),
                'status': process.status(),
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent(),
                'create_time': datetime.fromtimestamp(process.create_time()).isoformat()
            }
        except Exception as e:
            log_error(f"Failed to get process info: {e}")
            return None
    
    def _is_command_allowed(self, command: Union[str, List[str]]) -> bool:
        """Check if a command is allowed by security policy."""
        if isinstance(command, str):
            # Split into parts
            parts = command.split()
            cmd = parts[0] if parts else ''
        else:
            cmd = command[0] if command else ''
        
        # Check blacklist
        for banned in self.blacklist:
            if banned in cmd:
                return False
        
        # If whitelist is empty, allow all (except blacklisted)
        if not self.whitelist:
            return True
        
        # Check whitelist
        for allowed in self.whitelist:
            if allowed in cmd:
                return True
        
        return False
    
    # ============================================================
    # Tool Management
    # ============================================================
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """
        Get the path to a tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Optional[str]: Path to tool or None
        """
        # Check config for tool path
        config_path = get_config(f'tools.{tool_name}.path', None)
        if config_path and os.path.exists(config_path):
            return config_path
        
        # Check common locations
        common_paths = [
            f'/usr/bin/{tool_name}',
            f'/usr/local/bin/{tool_name}',
            f'/opt/bugbounty-tools/{tool_name}/{tool_name}',
            f'/opt/{tool_name}/{tool_name}',
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        # Check if in PATH
        import shutil
        path = shutil.which(tool_name)
        if path:
            return path
        
        return None
    
    def is_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed."""
        return self.get_tool_path(tool_name) is not None
    
    def install_tool(self, tool_name: str) -> bool:
        """
        Install a tool.
        
        Args:
            tool_name: Name of the tool to install
            
        Returns:
            bool: Success status
        """
        log_info(f"Installing tool: {tool_name}")
        
        # Map tool names to installation commands
        install_commands = {
            'nmap': ['sudo', 'apt-get', 'install', '-y', 'nmap'],
            'nuclei': ['curl', '-L', 'https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip', '-o', '/tmp/nuclei.zip'],
            'subfinder': ['curl', '-L', 'https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip', '-o', '/tmp/subfinder.zip'],
            'amass': ['sudo', 'apt-get', 'install', '-y', 'amass'],
            'ffuf': ['curl', '-L', 'https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64.tar.gz', '-o', '/tmp/ffuf.tar.gz'],
            'sqlmap': ['sudo', 'apt-get', 'install', '-y', 'sqlmap'],
            'nikto': ['sudo', 'apt-get', 'install', '-y', 'nikto'],
            'wpscan': ['sudo', 'gem', 'install', 'wpscan'],
        }
        
        if tool_name not in install_commands:
            log_warning(f"No installation command found for: {tool_name}")
            return False
        
        # Check if already installed
        if self.is_tool_installed(tool_name):
            log_info(f"Tool already installed: {tool_name}")
            return True
        
        # Run installation
        result = self.run_command(install_commands[tool_name], timeout=300)
        
        if result['success']:
            log_info(f"Tool installed successfully: {tool_name}")
            return True
        else:
            log_error(f"Tool installation failed: {tool_name}")
            return False
    
    def run_tool(self, tool_name: str, args: List[str] = None) -> Dict[str, Any]:
        """
        Run a security tool with arguments.
        
        Args:
            tool_name: Name of the tool
            args: Arguments to pass
            
        Returns:
            Dict: Command result
        """
        tool_path = self.get_tool_path(tool_name)
        if not tool_path:
            log_warning(f"Tool not found: {tool_name}")
            return {
                'success': False,
                'stdout': '',
                'stderr': f'Tool not found: {tool_name}',
                'returncode': -1,
                'command': f'{tool_name} {args}'
            }
        
        # Get tool configuration
        tool_config = get_config(f'tools.{tool_name}', {})
        
        # Build command
        cmd = [tool_path]
        
        # Add default args from config
        default_args = tool_config.get('args', '')
        if default_args:
            cmd.extend(default_args.split())
        
        # Add custom args
        if args:
            cmd.extend(args)
        
        return self.run_command(cmd, timeout=300)
    
    # ============================================================
    # Burp Suite Professional Integration
    # ============================================================
    
    def burp_connect(self) -> bool:
        """
        Connect to Burp Suite Professional API.
        
        Returns:
            bool: Success status
        """
        if not self.burp_config['enabled']:
            log_warning("Burp Suite is disabled in configuration")
            return False
        
        log_info("Connecting to Burp Suite Professional...")
        
        # Check if Burp is running
        if not self.burp_is_running():
            log_warning("Burp Suite is not running. Starting it...")
            if not self.burp_start():
                return False
        
        # Test connection
        try:
            import requests
            url = f"http://127.0.0.1:{self.burp_config['api_port']}/burp"
            headers = {}
            if self.burp_config.get('api_key'):
                headers['Authorization'] = f'Bearer {self.burp_config["api_key"]}'
            
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                log_info("Burp Suite Professional connected successfully")
                return True
            else:
                log_error(f"Burp connection failed: {response.status_code}")
                return False
                
        except ImportError:
            log_warning("Requests library not available. Using fallback check...")
            # Simple port check
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', self.burp_config['api_port']))
            sock.close()
            if result == 0:
                log_info("Burp Suite Professional appears to be running")
                return True
            else:
                log_error("Burp Suite Professional not accessible")
                return False
                
        except Exception as e:
            log_error(f"Burp connection failed: {e}")
            return False
    
    def burp_start(self) -> bool:
        """
        Start Burp Suite Professional.
        
        Returns:
            bool: Success status
        """
        burp_path = self.burp_config.get('path')
        
        if not burp_path or not os.path.exists(burp_path):
            # Try common locations
            common_paths = [
                '/usr/local/bin/burpsuite',
                '/usr/bin/burpsuite',
                '/opt/BurpSuitePro/BurpSuitePro',
                '/Applications/Burp Suite Professional.app/Contents/MacOS/BurpSuitePro',
                'C:\\Program Files\\BurpSuitePro\\BurpSuitePro.exe'
            ]
            
            for path in common_paths:
                if os.path.exists(path):
                    burp_path = path
                    break
        
        if not burp_path or not os.path.exists(burp_path):
            log_error("Burp Suite Professional not found")
            return False
        
        log_info(f"Starting Burp Suite: {burp_path}")
        
        # Start Burp in background
        try:
            # Start with REST API enabled
            cmd = [
                burp_path,
                '--rest-api-port', str(self.burp_config['api_port']),
                '--rest-api-login', 'admin',
                '--rest-api-password', 'admin'
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False
            )
            
            log_info(f"Burp Suite started with PID: {process.pid}")
            
            # Wait for it to be ready
            import time
            for _ in range(30):  # 30 seconds timeout
                time.sleep(1)
                if self.burp_is_running():
                    log_info("Burp Suite is ready")
                    return True
            
            log_warning("Burp Suite started but may not be ready")
            return True
            
        except Exception as e:
            log_error(f"Failed to start Burp Suite: {e}")
            return False
    
    def burp_is_running(self) -> bool:
        """Check if Burp Suite is running."""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', self.burp_config['api_port']))
            sock.close()
            return result == 0
        except:
            return False
    
    def burp_stop(self) -> bool:
        """Stop Burp Suite Professional."""
        try:
            # Find Burp processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if 'burp' in proc.info['name'].lower():
                        proc.terminate()
                        log_info(f"Stopped Burp process: {proc.info['pid']}")
                except:
                    pass
            
            log_info("Burp Suite stopped")
            return True
            
        except Exception as e:
            log_error(f"Failed to stop Burp: {e}")
            return False
    
    def burp_send_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Send a request through Burp Suite for analysis.
        
        Args:
            request: Request data (method, url, headers, body)
            
        Returns:
            Optional[Dict]: Response with analysis
        """
        if not self.burp_connect():
            return None
        
        try:
            import requests
            
            # Build request
            url = f"http://127.0.0.1:{self.burp_config['api_port']}/v0.1/scan"
            headers = {
                'Content-Type': 'application/json'
            }
            if self.burp_config.get('api_key'):
                headers['Authorization'] = f'Bearer {self.burp_config["api_key"]}'
            
            # Send to Burp for scanning
            payload = {
                'url': request.get('url'),
                'method': request.get('method', 'GET'),
                'headers': request.get('headers', {}),
                'body': request.get('body', '')
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                log_error(f"Burp scan failed: {response.status_code}")
                return None
                
        except Exception as e:
            log_error(f"Burp request failed: {e}")
            return None
    
    def burp_get_issues(self) -> List[Dict[str, Any]]:
        """
        Get issues from Burp Suite.
        
        Returns:
            List[Dict]: List of issues
        """
        if not self.burp_connect():
            return []
        
        try:
            import requests
            
            url = f"http://127.0.0.1:{self.burp_config['api_port']}/v0.1/issues"
            headers = {}
            if self.burp_config.get('api_key'):
                headers['Authorization'] = f'Bearer {self.burp_config["api_key"]}'
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response.json().get('issues', [])
            else:
                log_error(f"Failed to get Burp issues: {response.status_code}")
                return []
                
        except Exception as e:
            log_error(f"Failed to get Burp issues: {e}")
            return []
    
    def burp_export_issues(self, filepath: str) -> bool:
        """
        Export Burp issues to a file.
        
        Args:
            filepath: Path to save issues
            
        Returns:
            bool: Success status
        """
        issues = self.burp_get_issues()
        if not issues:
            log_warning("No issues found in Burp")
            return False
        
        try:
            with open(filepath, 'w') as f:
                json.dump(issues, f, indent=2, default=str)
            log_info(f"Burp issues exported to: {filepath}")
            return True
        except Exception as e:
            log_error(f"Failed to export Burp issues: {e}")
            return False
    
    # ============================================================
    # File Operations
    # ============================================================
    
    def file_exists(self, path: str) -> bool:
        """Check if a file exists."""
        return os.path.exists(path) and os.path.isfile(path)
    
    def directory_exists(self, path: str) -> bool:
        """Check if a directory exists."""
        return os.path.exists(path) and os.path.isdir(path)
    
    def read_file(self, path: str) -> Optional[str]:
        """Read a file's contents."""
        try:
            with open(path, 'r') as f:
                return f.read()
        except Exception as e:
            log_error(f"Failed to read file: {e}")
            return None
    
    def write_file(self, path: str, content: str) -> bool:
        """Write content to a file."""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                f.write(content)
            log_debug(f"File written: {path}")
            return True
        except Exception as e:
            log_error(f"Failed to write file: {e}")
            return False
    
    def append_file(self, path: str, content: str) -> bool:
        """Append content to a file."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'a') as f:
                f.write(content)
            return True
        except Exception as e:
            log_error(f"Failed to append file: {e}")
            return False
    
    def list_files(self, directory: str, pattern: str = '*') -> List[str]:
        """List files in a directory."""
        try:
            import glob
            return glob.glob(f"{directory}/{pattern}")
        except Exception as e:
            log_error(f"Failed to list files: {e}")
            return []
    
    def create_directory(self, path: str) -> bool:
        """Create a directory."""
        try:
            os.makedirs(path, exist_ok=True)
            return True
        except Exception as e:
            log_error(f"Failed to create directory: {e}")
            return False
    
    def delete_file(self, path: str) -> bool:
        """Delete a file."""
        try:
            if os.path.isfile(path):
                os.remove(path)
                log_debug(f"File deleted: {path}")
            return True
        except Exception as e:
            log_error(f"Failed to delete file: {e}")
            return False
    
    def delete_directory(self, path: str) -> bool:
        """Delete a directory and its contents."""
        try:
            if os.path.exists(path):
                shutil.rmtree(path)
                log_debug(f"Directory deleted: {path}")
            return True
        except Exception as e:
            log_error(f"Failed to delete directory: {e}")
            return False
    
    # ============================================================
    # Environment Management
    # ============================================================
    
    def get_env_var(self, key: str) -> Optional[str]:
        """Get an environment variable."""
        return os.environ.get(key)
    
    def set_env_var(self, key: str, value: str) -> bool:
        """Set an environment variable."""
        try:
            os.environ[key] = value
            return True
        except Exception as e:
            log_error(f"Failed to set env var: {e}")
            return False
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        try:
            info = {
                'os': sys.platform,
                'python_version': sys.version,
                'cpu_count': psutil.cpu_count(),
                'cpu_percent': psutil.cpu_percent(),
                'memory_total': psutil.virtual_memory().total,
                'memory_available': psutil.virtual_memory().available,
                'disk_usage': psutil.disk_usage('/')._asdict(),
                'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                'working_dir': self.working_dir
            }
            return info
        except Exception as e:
            log_error(f"Failed to get system info: {e}")
            return {}