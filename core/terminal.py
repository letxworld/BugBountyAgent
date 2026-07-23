"""
BugBountyAgent - Terminal Controller
======================================
Controls your terminal like a human.
Runs commands, installs tools, executes scripts.
"""

import os
import subprocess
import shutil
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from .config import Config
from .logging import log_info, log_error, log_warning, log_debug


@dataclass
class CommandResult:
    """Result of a command execution."""
    command: str
    stdout: str
    stderr: str
    returncode: int
    success: bool
    duration: float


class TerminalController:
    """
    Controls the terminal like a human.
    Runs commands, installs tools, manages processes.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.working_dir = config.get('system.working_dir', '.')
        self.whitelist = config.get('system.command_whitelist', [])
        self.blacklist = config.get('system.command_blacklist', [])
        self.timeout = config.get('system.command_timeout', 300)
        
        log_info("💻 TerminalController initialized")
    
    # ============================================================
    # Command Execution
    # ============================================================
    
    def run(self, command: str, timeout: Optional[int] = None, 
            shell: bool = True, env: Optional[Dict] = None) -> CommandResult:
        """
        Run a command in the terminal.
        
        Args:
            command: Command to run
            timeout: Timeout in seconds
            shell: Run in shell mode
            env: Environment variables
            
        Returns:
            CommandResult: Result of the command
        """
        # Security checks
        if not self._is_command_allowed(command):
            log_warning(f"🚫 Command blocked: {command}")
            return CommandResult(
                command=command,
                stdout='',
                stderr='Command blocked by security policy',
                returncode=-1,
                success=False,
                duration=0
            )
        
        log_info(f"💻 Running: {command}")
        start_time = time.time()
        
        try:
            full_env = os.environ.copy()
            if env:
                full_env.update(env)
            
            # Use bash for better shell compatibility
            if shell:
                cmd = ['/bin/bash', '-c', command]
            else:
                cmd = command if isinstance(command, list) else [command]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                env=full_env,
                cwd=self.working_dir
            )
            
            duration = time.time() - start_time
            
            success = result.returncode == 0
            
            if success:
                log_debug(f"✅ Command succeeded: {command[:50]}...")
            else:
                log_warning(f"⚠️ Command failed: {command[:50]}... (code {result.returncode})")
                if result.stderr:
                    log_debug(f"   Error: {result.stderr[:200]}")
            
            return CommandResult(
                command=command,
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                success=success,
                duration=duration
            )
            
        except subprocess.TimeoutExpired:
            log_error(f"⏰ Command timed out: {command[:50]}...")
            return CommandResult(
                command=command,
                stdout='',
                stderr=f'Command timed out after {timeout or self.timeout}s',
                returncode=-1,
                success=False,
                duration=timeout or self.timeout
            )
        except Exception as e:
            log_error(f"❌ Command failed: {e}")
            return CommandResult(
                command=command,
                stdout='',
                stderr=str(e),
                returncode=-1,
                success=False,
                duration=time.time() - start_time
            )
    
    def run_background(self, command: str, env: Optional[Dict] = None) -> Optional[subprocess.Popen]:
        """Run a command in the background."""
        if not self._is_command_allowed(command):
            log_warning(f"🚫 Command blocked: {command}")
            return None
        
        try:
            full_env = os.environ.copy()
            if env:
                full_env.update(env)
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=full_env,
                cwd=self.working_dir
            )
            
            log_debug(f"🔄 Background process started: {process.pid}")
            return process
            
        except Exception as e:
            log_error(f"❌ Background process failed: {e}")
            return None
    
    # ============================================================
    # Tool Installation
    # ============================================================
    
    def install_tool(self, tool_name: str) -> bool:
        """Install a security tool."""
        if self.is_tool_installed(tool_name):
            log_info(f"✅ {tool_name} already installed")
            return True
        
        log_info(f"📦 Installing: {tool_name}")
        
        install_commands = {
            'nmap': 'sudo apt-get install -y nmap 2>/dev/null || brew install nmap 2>/dev/null || echo "⚠️ Please install nmap manually"',
            'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 2>/dev/null || curl -s https://raw.githubusercontent.com/projectdiscovery/nuclei/main/install.sh | bash 2>/dev/null || echo "⚠️ Please install nuclei manually"',
            'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || echo "⚠️ Please install subfinder manually"',
            'amass': 'go install -v github.com/OWASP/Amass/v3/...@master 2>/dev/null || sudo apt-get install -y amass 2>/dev/null || echo "⚠️ Please install amass manually"',
            'ffuf': 'go install -v github.com/ffuf/ffuf@latest 2>/dev/null || echo "⚠️ Please install ffuf manually"',
            'sqlmap': 'sudo apt-get install -y sqlmap 2>/dev/null || brew install sqlmap 2>/dev/null || echo "⚠️ Please install sqlmap manually"',
            'nikto': 'sudo apt-get install -y nikto 2>/dev/null || brew install nikto 2>/dev/null || echo "⚠️ Please install nikto manually"',
            'wpscan': 'sudo gem install wpscan 2>/dev/null || echo "⚠️ Please install wpscan manually"',
        }
        
        if tool_name not in install_commands:
            log_error(f"❌ No install command for: {tool_name}")
            return False
        
        result = self.run(install_commands[tool_name], timeout=600)
        return result.success
    
    def is_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed."""
        return shutil.which(tool_name) is not None
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get the path of a tool."""
        return shutil.which(tool_name)
    
    def _is_command_allowed(self, command: str) -> bool:
        """Check if a command is allowed by security policy."""
        command_lower = command.lower()
        
        for banned in self.blacklist:
            if banned in command_lower:
                return False
        
        if not self.whitelist:
            return True
        
        for allowed in self.whitelist:
            if allowed in command_lower:
                return True
        
        return False
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        info = {
            'os': os.name,
            'working_dir': self.working_dir,
            'path': os.environ.get('PATH', '')
        }
        
        result = self.run("python3 --version")
        if result.success:
            info['python'] = result.stdout.strip()
        
        result = self.run("uname -a")
        if result.success:
            info['system'] = result.stdout.strip()
        
        return info
