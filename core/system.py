"""
BugBountyAgent - System Controller
====================================
FULL SYSTEM ACCESS like Anydesk/TeamViewer.
Controls your entire laptop:
- Browser automation
- Terminal commands
- File system operations
- Process management
- Tool installation
- Burp Suite integration
- Metasploit integration
"""

import os
import sys
import time
import subprocess
import shutil
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime

from .config import Config
from .browser import BrowserController
from .terminal import TerminalController
from .filesystem import FileSystemController
from .process import ProcessController
from .logging import log_info, log_error, log_warning, log_debug
from .utils import get_timestamp


class SystemController:
    """
    FULL SYSTEM ACCESS controller.
    Controls your laptop like a human bug bounty hunter.
    """
    
    def __init__(self, config: Config):
        self.config = config
        
        # Initialize all controllers
        self.browser = BrowserController(config)
        self.terminal = TerminalController(config)
        self.filesystem = FileSystemController(config)
        self.process = ProcessController(config)
        
        # Burp Suite settings
        self.burp_enabled = config.get('tools.burp.enabled', False)
        self.burp_path = config.get('tools.burp.path', '/usr/local/bin/burpsuite')
        self.burp_port = config.get('tools.burp.port', 8080)
        self.burp_process = None
        
        # Metasploit settings
        self.msf_enabled = config.get('tools.metasploit.enabled', False)
        self.msf_path = config.get('tools.metasploit.path', '/usr/bin/msfconsole')
        
        # State
        self.is_connected = False
        
        log_info("💻 SystemController initialized — FULL SYSTEM ACCESS")
    
    # ============================================================
    # Connection
    # ============================================================
    
    def connect(self) -> bool:
        """Connect to the system like Anydesk/TeamViewer."""
        log_info("🔗 Connecting to system...")
        
        # Connect browser
        if not self.browser.connect():
            log_warning("Browser connection failed")
        
        self.is_connected = True
        log_info("✅ System connected")
        return True
    
    def disconnect(self):
        """Disconnect from system."""
        self.browser.disconnect()
        self.process.stop_all()
        self.is_connected = False
        log_info("🔌 System disconnected")
    
    # ============================================================
    # 1. Browser Control (Like a Human)
    # ============================================================
    
    def open_browser(self, url: Optional[str] = None) -> bool:
        """Open browser and navigate to URL."""
        if not self.browser.ensure_connected():
            return False
        
        if url:
            return self.browser.navigate(url)
        return True
    
    def navigate(self, url: str) -> bool:
        """Navigate to a URL in browser."""
        return self.browser.navigate(url)
    
    def click(self, selector: str) -> bool:
        """Click an element on the page."""
        return self.browser.click(selector)
    
    def type_text(self, text: str, selector: Optional[str] = None) -> bool:
        """Type text like a human."""
        if selector:
            return self.browser.fill(selector, text)
        return self.browser.type_text(text)
    
    def screenshot(self, name: Optional[str] = None) -> Optional[str]:
        """Take screenshot of current page."""
        return self.browser.screenshot(name)
    
    def get_page_html(self) -> Optional[str]:
        """Get current page HTML."""
        return self.browser.get_html()
    
    def get_page_url(self) -> Optional[str]:
        """Get current page URL."""
        return self.browser.get_url()
    
    def execute_javascript(self, js: str) -> Any:
        """Execute JavaScript in browser."""
        return self.browser.evaluate(js)
    
    # ============================================================
    # 2. Terminal/Command Execution
    # ============================================================
    
    def run_command(self, command: str, timeout: Optional[int] = None) -> Dict:
        """Run a command in terminal like a human."""
        result = self.terminal.run(command, timeout)
        return {
            'success': result.success,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'duration': result.duration
        }
    
    def run_background(self, command: str) -> Optional[subprocess.Popen]:
        """Run command in background."""
        return self.terminal.run_background(command)
    
    def install_tool(self, tool_name: str) -> bool:
        """Install a security tool."""
        return self.terminal.install_tool(tool_name)
    
    def is_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed."""
        return self.terminal.is_tool_installed(tool_name)
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get tool path."""
        return self.terminal.get_tool_path(tool_name)
    
    # ============================================================
    # 3. File System Operations
    # ============================================================
    
    def read_file(self, path: str) -> Optional[str]:
        """Read a file."""
        return self.filesystem.read_file(path)
    
    def write_file(self, path: str, content: str) -> bool:
        """Write to a file."""
        return self.filesystem.write_file(path, content)
    
    def write_json(self, path: str, data: Dict) -> bool:
        """Write JSON to a file."""
        return self.filesystem.write_json(path, data)
    
    def read_json(self, path: str) -> Optional[Dict]:
        """Read JSON from a file."""
        return self.filesystem.read_json(path)
    
    def list_files(self, path: str, pattern: str = '*') -> List[str]:
        """List files in a directory."""
        return self.filesystem.list_files(path, pattern)
    
    def delete_file(self, path: str) -> bool:
        """Delete a file."""
        return self.filesystem.delete_file(path)
    
    def create_directory(self, path: str) -> bool:
        """Create a directory."""
        return self.filesystem.create_directory(path)
    
    def file_exists(self, path: str) -> bool:
        """Check if file exists."""
        return self.filesystem.file_exists(path)
    
    # ============================================================
    # 4. Process Management
    # ============================================================
    
    def start_process(self, command: str, name: Optional[str] = None) -> Optional[subprocess.Popen]:
        """Start a process."""
        return self.process.start(command, name)
    
    def stop_process(self, name: str, force: bool = False) -> bool:
        """Stop a process."""
        return self.process.stop(name, force)
    
    def stop_all_processes(self) -> int:
        """Stop all processes."""
        return self.process.stop_all()
    
    def get_running_processes(self) -> List[Dict]:
        """Get running processes."""
        return self.process.get_processes()
    
    def is_process_running(self, name: str) -> bool:
        """Check if process is running."""
        return self.process.is_running(name)
    
    # ============================================================
    # 5. Burp Suite Integration
    # ============================================================
    
    def burp_start(self) -> bool:
        """Start Burp Suite Professional."""
        if not self.burp_enabled:
            log_warning("Burp Suite is disabled in config")
            return False
        
        if not os.path.exists(self.burp_path):
            log_error(f"Burp Suite not found at: {self.burp_path}")
            return False
        
        log_info(f"🔧 Starting Burp Suite: {self.burp_path}")
        
        try:
            cmd = [
                self.burp_path,
                '--rest-api-port', str(self.burp_port),
                '--rest-api-login', 'admin',
                '--rest-api-password', 'admin'
            ]
            
            self.burp_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False
            )
            
            # Wait for it to be ready
            time.sleep(3)
            log_info(f"✅ Burp Suite started (PID: {self.burp_process.pid})")
            return True
            
        except Exception as e:
            log_error(f"Failed to start Burp: {e}")
            return False
    
    def burp_stop(self) -> bool:
        """Stop Burp Suite."""
        if self.burp_process:
            try:
                self.burp_process.terminate()
                self.burp_process = None
                log_info("✅ Burp Suite stopped")
                return True
            except Exception as e:
                log_error(f"Failed to stop Burp: {e}")
                return False
        return False
    
    def burp_is_running(self) -> bool:
        """Check if Burp Suite is running."""
        if self.burp_process:
            return self.burp_process.poll() is None
        return False
    
    def burp_send_request(self, url: str, method: str = 'GET', 
                          headers: Dict = None, body: str = None) -> Optional[Dict]:
        """Send request through Burp Suite."""
        if not self.burp_is_running():
            log_warning("Burp Suite not running")
            return None
        
        try:
            import requests
            burp_url = f"http://127.0.0.1:{self.burp_port}/v0.1/scan"
            
            payload = {
                'url': url,
                'method': method,
                'headers': headers or {},
                'body': body or ''
            }
            
            response = requests.post(burp_url, json=payload, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                log_error(f"Burp request failed: {response.status_code}")
                return None
                
        except Exception as e:
            log_error(f"Burp request error: {e}")
            return None
    
    def burp_get_issues(self) -> List[Dict]:
        """Get issues from Burp Suite."""
        if not self.burp_is_running():
            return []
        
        try:
            import requests
            url = f"http://127.0.0.1:{self.burp_port}/v0.1/issues"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                return response.json().get('issues', [])
            return []
            
        except Exception as e:
            log_error(f"Failed to get Burp issues: {e}")
            return []
    
    # ============================================================
    # 6. Metasploit Integration
    # ============================================================
    
    def msf_start(self) -> bool:
        """Start Metasploit console."""
        if not self.msf_enabled:
            log_warning("Metasploit is disabled in config")
            return False
        
        if not os.path.exists(self.msf_path):
            log_error(f"Metasploit not found at: {self.msf_path}")
            return False
        
        log_info("🔧 Starting Metasploit...")
        return True
    
    def msf_run_exploit(self, exploit: str, target: str, options: Dict) -> Dict:
        """Run a Metasploit exploit."""
        if not self.msf_enabled:
            return {'success': False, 'error': 'Metasploit disabled'}
        
        log_info(f"💀 Running exploit: {exploit} on {target}")
        
        # Build command
        cmd = f"msfconsole -q -x 'use {exploit}; set RHOSTS {target};"
        for key, value in options.items():
            cmd += f" set {key} {value};"
        cmd += " run; exit'"
        
        result = self.run_command(cmd, timeout=300)
        
        return {
            'success': result['success'],
            'output': result['stdout'],
            'error': result['stderr']
        }
    
    # ============================================================
    # 7. Full System Access (Like Anydesk)
    # ============================================================
    
    def take_control(self) -> Dict[str, Any]:
        """
        Take full control of the system.
        Like Anydesk/TeamViewer — full system access.
        """
        log_info("🎮 Taking full system control...")
        
        control = {
            'connected': self.connect(),
            'browser': {
                'controlled': self.browser.is_connected,
                'can_navigate': True,
                'can_click': True,
                'can_type': True
            },
            'terminal': {
                'available': True,
                'can_run_commands': True,
                'can_install_tools': True
            },
            'filesystem': {
                'available': True,
                'can_read': True,
                'can_write': True,
                'can_delete': True
            },
            'process': {
                'available': True,
                'can_start': True,
                'can_stop': True,
                'can_monitor': True
            },
            'tools': {
                'burp': self.burp_enabled and self.burp_is_running(),
                'metasploit': self.msf_enabled
            },
            'timestamp': get_timestamp()
        }
        
        log_info("✅ System control active")
        return control
    
    def release_control(self) -> bool:
        """Release system control."""
        self.disconnect()
        log_info("🎮 System control released")
        return True
    
    # ============================================================
    # 8. System Information
    # ============================================================
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get complete system information."""
        info = {
            'os': os.name,
            'working_dir': os.getcwd(),
            'python_version': sys.version,
            'browser_connected': self.browser.is_connected if hasattr(self.browser, 'is_connected') else False,
            'burp_running': self.burp_is_running(),
            'processes': self.get_running_processes(),
            'timestamp': get_timestamp()
        }
        
        return info
    
    # ============================================================
    # 9. Transparency - What It CAN'T Do
    # ============================================================
    
    def tell_limitations(self) -> Dict[str, str]:
        """
        Tell the user what the agent CANNOT do.
        Transparency is key for trust.
        """
        return {
            'business_logic': "❌ Cannot find business logic bugs (requires human understanding of app purpose)",
            'complex_flow': "❌ Cannot understand complex application flow without human guidance",
            '0day_exploits': "❌ Cannot find 0-day vulnerabilities (only known CVEs and patterns)",
            'human_judgment': "❌ Cannot replace human judgment — all findings should be verified",
            'physical_access': "❌ Cannot perform physical security testing",
            'social_engineering': "❌ Cannot perform social engineering attacks",
            'legal_authorization': "⚠️ Requires user to have explicit authorization to test targets"
        }
    
    # ============================================================
    # 10. Cleanup
    # ============================================================
    
    def cleanup_old_data(self, days: int = 30) -> Dict[str, int]:
        """Clean up old data."""
        return self.filesystem.cleanup_old_files(days)