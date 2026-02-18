"""Tool Detection and Installation Management"""

import shutil
import subprocess
import logging
import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Optional

from scripts.installer.core.os_detector import OSDetector

logger = logging.getLogger(__name__)


@dataclass
class InstallStatus:
    """Status of a tool installation check"""
    installed: bool
    path: Optional[str] = None
    version: Optional[str] = None


@dataclass
class InstallResult:
    """Result of a tool installation attempt"""
    success: bool
    tool: str
    package: Optional[str] = None
    error: Optional[str] = None
    output: Optional[str] = None


class ToolManager:
    """Manages tool detection and installation"""

    def __init__(self, os_detector: OSDetector):
        self.os_detector = os_detector
        self.registry = self._load_registry()

    def _load_registry(self) -> Dict[str, Any]:
        """Load tool registry from YAML"""
        registry_path = Path('scripts/installer/registry.yaml')

        if not registry_path.exists():
            logger.warning("Tool registry not found, using empty registry")
            return {'tools': {}}

        with open(registry_path) as f:
            return yaml.safe_load(f)

    def check_installed(self, tool_name: str) -> InstallStatus:
        """Check if a tool is already installed"""
        # Method 1: Check with 'which'
        path = shutil.which(tool_name)
        if path:
            # Do NOT call _get_version() here — GUI tools like Ghidra open their
            # interface instead of printing a version string, crashing test runs.
            return InstallStatus(installed=True, path=path, version=None)

        # Method 2: Check package manager
        package_name = self.get_package_name(tool_name)
        if self._check_dpkg(package_name):
            return InstallStatus(installed=True, path=f"/usr/bin/{tool_name}")

        return InstallStatus(installed=False)

    def _get_version(self, tool_name: str) -> Optional[str]:
        """Try to get tool version"""
        try:
            result = subprocess.run(
                [tool_name, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Parse first line of version output
            return result.stdout.split('\n')[0][:50]
        except:
            return None

    def _check_dpkg(self, package_name: str) -> bool:
        """Check if package is installed via dpkg"""
        try:
            result = subprocess.run(
                ['dpkg', '-l', package_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0 and 'ii' in result.stdout
        except:
            return False

    def get_package_name(self, tool_name: str) -> str:
        """Get package name for a tool from registry"""
        tools = self.registry.get('tools', {})
        if tool_name in tools:
            return tools[tool_name].get('package', tool_name)
        return tool_name

    def get_category(self, tool_name: str) -> str:
        """Get category for a tool"""
        tools = self.registry.get('tools', {})
        if tool_name in tools:
            return tools[tool_name].get('category', 'unknown')
        return 'unknown'

    def get_tier(self, tool_name: str) -> str:
        """Get tier for a tool"""
        tools = self.registry.get('tools', {})
        if tool_name in tools:
            return tools[tool_name].get('tier', 'core')
        return 'core'

    def get_manager(self, tool_name: str) -> str:
        """Get package manager for a tool"""
        tools = self.registry.get('tools', {})
        if tool_name in tools:
            return tools[tool_name].get('manager', 'apt')
        return 'apt'

    def install_tool(self, tool_name: str) -> InstallResult:
        """Install a single tool"""
        package_name = self.get_package_name(tool_name)
        manager = self.get_manager(tool_name)

        logger.info(f"Installing {tool_name} ({package_name}) via {manager}")

        try:
            if manager == 'apt':
                return self._install_apt(tool_name, package_name)
            elif manager == 'pip':
                return self._install_pip(tool_name, package_name)
            elif manager == 'npm':
                return self._install_npm(tool_name, package_name)
            else:
                return InstallResult(
                    success=False,
                    tool=tool_name,
                    error=f"Unsupported package manager: {manager}"
                )

        except Exception as e:
            logger.error(f"Error installing {tool_name}: {e}")
            return InstallResult(
                success=False,
                tool=tool_name,
                error=str(e)
            )

    def _install_apt(self, tool_name: str, package_name: str) -> InstallResult:
        """Install via apt-get"""
        result = subprocess.run(
            ['apt-get', 'install', '-y', package_name],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode == 0:
            return InstallResult(
                success=True,
                tool=tool_name,
                package=package_name,
                output=result.stdout
            )
        else:
            return InstallResult(
                success=False,
                tool=tool_name,
                package=package_name,
                error=result.stderr,
                output=result.stdout
            )

    def _install_pip(self, tool_name: str, package_name: str) -> InstallResult:
        """Install via pip"""
        result = subprocess.run(
            ['pip3', 'install', package_name],
            capture_output=True,
            text=True,
            timeout=180
        )

        return InstallResult(
            success=result.returncode == 0,
            tool=tool_name,
            package=package_name,
            error=result.stderr if result.returncode != 0 else None,
            output=result.stdout
        )

    def _install_npm(self, tool_name: str, package_name: str) -> InstallResult:
        """Install via npm"""
        result = subprocess.run(
            ['npm', 'install', '-g', package_name],
            capture_output=True,
            text=True,
            timeout=180
        )

        return InstallResult(
            success=result.returncode == 0,
            tool=tool_name,
            package=package_name,
            error=result.stderr if result.returncode != 0 else None,
            output=result.stdout
        )

    def scan_tools(self, tool_list: List[str]) -> tuple[List[str], List[str]]:
        """Scan tools and return (installed, missing) lists"""
        installed = []
        missing = []

        for tool in tool_list:
            status = self.check_installed(tool)
            if status.installed:
                installed.append(tool)
            else:
                missing.append(tool)

        logger.info(f"Scan complete: {len(installed)} installed, {len(missing)} missing")
        return installed, missing
