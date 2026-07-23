"""
BugBountyAgent - Tool Management
==================================
Install, update, and run all security tools.
"""

import os
import subprocess
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from .config import Config
from .terminal import TerminalController
from .logging import log_info, log_error, log_warning, log_debug


@dataclass
class ToolInfo:
    """Information about a security tool."""
    name: str
    installed: bool
    path: Optional[str]
    version: Optional[str]
    enabled: bool


class ToolManager:
    """
    Manages all security tools.
    Installs, updates, and runs tools.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.terminal = TerminalController(config)
        
        self.tools = {
            'nmap': {
                'name': 'nmap',
                'install_cmd': 'sudo apt-get install -y nmap',
                'check_cmd': 'nmap --version',
                'enabled': True
            },
            'nuclei': {
                'name': 'nuclei',
                'install_cmd': 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
                'check_cmd': 'nuclei -version',
                'enabled': True
            },
            'subfinder': {
                'name': 'subfinder',
                'install_cmd': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                'check_cmd': 'subfinder -version',
                'enabled': True
            },
            'amass': {
                'name': 'amass',
                'install_cmd': 'go install -v github.com/OWASP/Amass/v3/...@master',
                'check_cmd': 'amass -version',
                'enabled': True
            },
            'ffuf': {
                'name': 'ffuf',
                'install_cmd': 'go install -v github.com/ffuf/ffuf@latest',
                'check_cmd': 'ffuf -version',
                'enabled': True
            },
            'sqlmap': {
                'name': 'sqlmap',
                'install_cmd': 'sudo apt-get install -y sqlmap',
                'check_cmd': 'sqlmap --version',
                'enabled': True
            },
            'nikto': {
                'name': 'nikto',
                'install_cmd': 'sudo apt-get install -y nikto',
                'check_cmd': 'nikto -Version',
                'enabled': True
            },
            'wpscan': {
                'name': 'wpscan',
                'install_cmd': 'sudo gem install wpscan',
                'check_cmd': 'wpscan --version',
                'enabled': True
            }
        }
        
        log_info("🔧 ToolManager initialized")
    
    def check_tool(self, tool_name: str) -> ToolInfo:
        """Check if a tool is installed and get its info."""
        tool_config = self.tools.get(tool_name, {})
        installed = self.terminal.is_tool_installed(tool_name)
        path = self.terminal.get_tool_path(tool_name) if installed else None
        
        version = None
        if installed and path:
            try:
                result = subprocess.run(
                    [path, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    version = result.stdout.strip().split('\n')[0][:50]
            except:
                pass
        
        return ToolInfo(
            name=tool_name,
            installed=installed,
            path=path,
            version=version,
            enabled=tool_config.get('enabled', True)
        )
    
    def check_all_tools(self) -> Dict[str, ToolInfo]:
        """Check all tools."""
        results = {}
        for tool_name in self.tools:
            results[tool_name] = self.check_tool(tool_name)
        return results
    
    def install_tool(self, tool_name: str) -> bool:
        """Install a tool."""
        if tool_name not in self.tools:
            log_error(f"Unknown tool: {tool_name}")
            return False
        
        tool_config = self.tools[tool_name]
        install_cmd = tool_config.get('install_cmd')
        
        if not install_cmd:
            log_error(f"No install command for: {tool_name}")
            return False
        
        log_info(f"📦 Installing {tool_name}...")
        result = self.terminal.run(install_cmd, timeout=600)
        return result.success
    
    def install_all_tools(self) -> Dict[str, bool]:
        """Install all tools."""
        results = {}
        for tool_name in self.tools:
            if not self.check_tool(tool_name).installed:
                results[tool_name] = self.install_tool(tool_name)
            else:
                results[tool_name] = True
        return results
    
    def run_tool(self, tool_name: str, args: List[str] = None) -> Dict[str, Any]:
        """Run a tool with arguments."""
        if tool_name not in self.tools:
            return {'success': False, 'error': f'Unknown tool: {tool_name}'}
        
        tool_path = self.terminal.get_tool_path(tool_name)
        if not tool_path:
            return {'success': False, 'error': f'Tool not installed: {tool_name}'}
        
        cmd = [tool_path]
        if args:
            cmd.extend(args)
        
        result = self.terminal.run(' '.join(cmd))
        return {
            'success': result.success,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    
    def get_installed_tools(self) -> List[str]:
        """Get list of installed tools."""
        installed = []
        for tool_name in self.tools:
            if self.terminal.is_tool_installed(tool_name):
                installed.append(tool_name)
        return installed
    
    def get_missing_tools(self) -> List[str]:
        """Get list of missing tools."""
        missing = []
        for tool_name in self.tools:
            if not self.terminal.is_tool_installed(tool_name):
                missing.append(tool_name)
        return missing