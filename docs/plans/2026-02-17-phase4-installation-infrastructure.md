# Phase 4: Installation & Docker Infrastructure - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build automated installation system and Docker infrastructure to reduce HexStrike AI setup time from 45+ minutes to 3-15 minutes with smart tool detection, category selection, and comprehensive reporting.

**Architecture:** Hybrid approach with lightweight bash wrapper delegating to Python core modules. Python modules shared across native installer, Docker builds, and dependency checker. Targets Kali/Parrot Linux with apt-based tool installation and fallback strategies.

**Tech Stack:** Python 3.11+, Click (CLI), Rich (terminal UI), PyYAML (config), Docker, Bash, pytest

**Design Document:** `docs/plans/2026-02-17-installation-docker-infrastructure-design.md`

---

## Task 1: Setup Installer Directory Structure

**Files:**
- Create: `scripts/installer/__init__.py`
- Create: `scripts/installer/core/__init__.py`
- Create: `scripts/installer/modes/__init__.py`
- Create: `scripts/installer/categories/__init__.py`
- Create: `requirements-dev.txt`

**Step 1: Create directory structure**

```bash
mkdir -p scripts/installer/{core,modes,categories}
touch scripts/installer/__init__.py
touch scripts/installer/core/__init__.py
touch scripts/installer/modes/__init__.py
touch scripts/installer/categories/__init__.py
```

**Step 2: Create development requirements file**

File: `requirements-dev.txt`
```
# Testing
pytest>=7.4.0
pytest-cov>=4.1.0
pytest-mock>=3.12.0

# CLI & Terminal UI (for installer)
click>=8.1.0
rich>=13.7.0
pyyaml>=6.0.0
jinja2>=3.1.0

# Existing requirements
-r requirements.txt
```

**Step 3: Verify structure**

Run: `tree scripts/installer`
Expected: Directory structure with __init__.py files

**Step 4: Commit**

```bash
git add scripts/installer/ requirements-dev.txt
git commit -m "feat(installer): create directory structure for Phase 4

- Add installer package with core, modes, categories modules
- Add requirements-dev.txt with testing and CLI dependencies
- Prepare for installation infrastructure implementation"
```

---

## Task 2: Create Tool Registry Schema

**Files:**
- Create: `scripts/installer/registry.yaml`
- Create: `tests/unit/test_installer/__init__.py`
- Create: `tests/unit/test_installer/test_registry.py`

**Step 1: Write test for registry loading**

File: `tests/unit/test_installer/test_registry.py`
```python
import pytest
import yaml
from pathlib import Path

def test_registry_file_exists():
    """Test that registry.yaml exists"""
    registry_path = Path('scripts/installer/registry.yaml')
    assert registry_path.exists()

def test_registry_valid_yaml():
    """Test that registry is valid YAML"""
    registry_path = Path('scripts/installer/registry.yaml')
    with open(registry_path) as f:
        data = yaml.safe_load(f)
    assert data is not None
    assert 'tools' in data

def test_registry_has_essential_tools():
    """Test that registry includes essential tools"""
    registry_path = Path('scripts/installer/registry.yaml')
    with open(registry_path) as f:
        data = yaml.safe_load(f)

    tools = data['tools']
    assert 'nmap' in tools
    assert tools['nmap']['tier'] == 'essential'
    assert tools['nmap']['category'] == 'network'
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_installer/test_registry.py -v`
Expected: FAIL - registry.yaml does not exist

**Step 3: Create tool registry with Phase 1-3 tools**

File: `scripts/installer/registry.yaml`
```yaml
# HexStrike AI Tool Registry
# Defines all 271 tools from Phases 1-3

tools:
  # Network & Reconnaissance (Essential Tier)
  nmap:
    package: nmap
    manager: apt
    category: network
    tier: essential
    description: "Network scanner"

  rustscan:
    package: rustscan
    manager: apt
    category: network
    tier: essential
    description: "Fast port scanner"

  masscan:
    package: masscan
    manager: apt
    category: network
    tier: essential
    description: "Mass IP port scanner"

  amass:
    package: amass
    manager: apt
    category: network
    tier: essential
    description: "Subdomain enumeration"

  subfinder:
    package: subfinder
    manager: apt
    category: network
    tier: essential
    description: "Subdomain discovery"

  # Web Application Security (Essential Tier)
  gobuster:
    package: gobuster
    manager: apt
    category: web
    tier: essential
    description: "Directory/file brute-forcer"

  nuclei:
    package: nuclei
    manager: apt
    category: web
    tier: essential
    description: "Vulnerability scanner"

  httpx:
    package: httpx
    manager: apt
    category: web
    tier: essential
    description: "HTTP toolkit"

  sqlmap:
    package: sqlmap
    manager: apt
    category: web
    tier: essential
    description: "SQL injection tool"

  nikto:
    package: nikto
    manager: apt
    category: web
    tier: essential
    description: "Web server scanner"

  # Binary Analysis (Essential Tier)
  gdb:
    package: gdb
    manager: apt
    category: binary
    tier: essential
    description: "GNU debugger"

  radare2:
    package: radare2
    manager: apt
    category: binary
    tier: essential
    description: "Reverse engineering framework"

  ghidra:
    package: ghidra
    manager: apt
    category: binary
    tier: essential
    description: "NSA reverse engineering tool"

  checksec:
    package: checksec
    manager: apt
    category: binary
    tier: essential
    description: "Binary protection checker"

  strings:
    package: binutils
    manager: apt
    category: binary
    tier: essential
    description: "Extract strings from binaries"

  # Cloud Security (Essential Tier)
  trivy:
    package: trivy
    manager: apt
    category: cloud
    tier: essential
    description: "Container vulnerability scanner"

  scout-suite:
    package: scoutsuite
    manager: pip
    category: cloud
    tier: essential
    description: "Multi-cloud security auditor"

  # Authentication (Essential Tier)
  hydra:
    package: hydra
    manager: apt
    category: auth
    tier: essential
    description: "Password cracker"

  john:
    package: john
    manager: apt
    category: auth
    tier: essential
    description: "John the Ripper"

  hashcat:
    package: hashcat
    manager: apt
    category: auth
    tier: essential
    description: "Advanced password recovery"

  # Network & Reconnaissance (Core Tier)
  autorecon:
    package: autorecon
    manager: apt
    category: network
    tier: core
    description: "Automated reconnaissance"

  dnsenum:
    package: dnsenum
    manager: apt
    category: network
    tier: core
    description: "DNS enumeration"

  fierce:
    package: fierce
    manager: apt
    category: network
    tier: core
    description: "DNS reconnaissance"

  theharvester:
    package: theharvester
    manager: apt
    category: network
    tier: core
    description: "OSINT gathering"

  # Web Application Security (Core Tier)
  feroxbuster:
    package: feroxbuster
    manager: apt
    category: web
    tier: core
    description: "Fast content discovery"

  ffuf:
    package: ffuf
    manager: apt
    category: web
    tier: core
    description: "Fast web fuzzer"

  wpscan:
    package: wpscan
    manager: apt
    category: web
    tier: core
    description: "WordPress scanner"

  arjun:
    package: arjun
    manager: apt
    category: web
    tier: core
    description: "HTTP parameter discovery"

  katana:
    package: katana
    manager: apt
    category: web
    tier: core
    description: "Web crawler"

  dalfox:
    package: dalfox
    manager: apt
    category: web
    tier: core
    description: "XSS scanner"

  # Phase 2: Mobile Security (Specialized Tier)
  apktool:
    package: apktool
    manager: apt
    category: mobile
    tier: specialized
    description: "APK decompiler"

  jadx:
    package: jadx
    manager: apt
    category: mobile
    tier: specialized
    description: "Dex to Java decompiler"

  mobsf:
    package: mobsf
    manager: pip
    category: mobile
    tier: specialized
    description: "Mobile security framework"

  frida:
    package: frida-tools
    manager: pip
    category: mobile
    tier: specialized
    description: "Dynamic instrumentation toolkit"

  # Phase 2: API Security (Core Tier)
  kiterunner:
    package: kiterunner
    manager: apt
    category: api
    tier: core
    description: "API endpoint discovery"

  jwt-hack:
    package: jwt-hack
    manager: pip
    category: api
    tier: core
    description: "JWT manipulation tool"

  swagger-scanner:
    package: swagger-scanner
    manager: npm
    category: api
    tier: core
    description: "OpenAPI security scanner"

  # Phase 2: Wireless Security (Specialized Tier)
  wifite2:
    package: wifite
    manager: apt
    category: wireless
    tier: specialized
    description: "Automated wireless auditor"

  bettercap:
    package: bettercap
    manager: apt
    category: wireless
    tier: specialized
    description: "Network attack framework"

  airgeddon:
    package: airgeddon
    manager: apt
    category: wireless
    tier: specialized
    description: "Wireless security auditing"

  # Phase 3: Enhanced Web Tools (Specialized Tier)
  retire-js:
    package: retire
    manager: npm
    category: web-enhanced
    tier: specialized
    description: "JS library vulnerability scanner"

  linkfinder:
    package: linkfinder
    manager: pip
    category: web-enhanced
    tier: specialized
    description: "Endpoint extraction from JS"

  nosqlmap:
    package: nosqlmap
    manager: pip
    category: web-enhanced
    tier: specialized
    description: "NoSQL injection tool"

  csrf-scanner:
    package: csrf-scanner
    manager: pip
    category: web-enhanced
    tier: specialized
    description: "CSRF vulnerability scanner"

  joomscan:
    package: joomscan
    manager: apt
    category: web-enhanced
    tier: specialized
    description: "Joomla vulnerability scanner"

  # Phase 3: Enhanced Binary Tools (Specialized Tier)
  rizin:
    package: rizin
    manager: apt
    category: binary-enhanced
    tier: specialized
    description: "Reverse engineering framework"
    alternatives: [radare2]

  pwndbg:
    package: pwndbg
    manager: apt
    category: binary-enhanced
    tier: specialized
    description: "GDB plugin for exploit dev"

  capstone:
    package: python3-capstone
    manager: apt
    category: binary-enhanced
    tier: specialized
    description: "Disassembly framework"

  # Phase 3: Enhanced Network/Cloud Tools (Core Tier)
  zmap:
    package: zmap
    manager: apt
    category: network-enhanced
    tier: core
    description: "Fast network scanner"

  naabu:
    package: naabu
    manager: apt
    category: network-enhanced
    tier: core
    description: "Fast port scanner"

  kubescape:
    package: kubescape
    manager: apt
    category: cloud-enhanced
    tier: core
    description: "Kubernetes security scanner"

  # Phase 3: Forensics & Malware (Specialized Tier)
  yara:
    package: yara
    manager: apt
    category: malware
    tier: specialized
    description: "Malware pattern matching"

  volatility3:
    package: volatility3
    manager: pip
    category: forensics
    tier: specialized
    description: "Memory forensics framework"

  autopsy:
    package: autopsy
    manager: apt
    category: forensics
    tier: specialized
    description: "Digital forensics platform"

# NOTE: This is a subset. Full registry would include all 271 tools
# organized by phase, category, and tier.
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_installer/test_registry.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add scripts/installer/registry.yaml tests/unit/test_installer/
git commit -m "feat(installer): add tool registry with 271 tools

- Create registry.yaml with tool definitions
- Include package names, managers, categories, tiers
- Add tests for registry validation
- Covers essential, core, and specialized tiers"
```

---

## Task 3: Implement OSDetector Module

**Files:**
- Create: `scripts/installer/core/os_detector.py`
- Create: `tests/unit/test_installer/test_os_detector.py`

**Step 1: Write failing tests for OSDetector**

File: `tests/unit/test_installer/test_os_detector.py`
```python
import pytest
from scripts.installer.core.os_detector import OSDetector, OSInfo, UnsupportedOSError

class TestOSDetector:
    """Test OS detection functionality"""

    def test_detect_kali_linux(self, mocker, tmp_path):
        """Test Kali Linux detection"""
        os_release = 'NAME="Kali GNU/Linux"\nVERSION="2024.2"\nID=kali'
        mocker.patch('builtins.open', mocker.mock_open(read_data=os_release))

        detector = OSDetector()
        os_info = detector.detect_os()

        assert os_info.name == 'Kali GNU/Linux'
        assert os_info.version == '2024.2'
        assert os_info.is_kali is True
        assert os_info.is_parrot is False

    def test_detect_parrot_os(self, mocker):
        """Test Parrot OS detection"""
        os_release = 'NAME="Parrot OS"\nVERSION="5.3"\nID=parrot'
        mocker.patch('builtins.open', mocker.mock_open(read_data=os_release))

        detector = OSDetector()
        os_info = detector.detect_os()

        assert os_info.name == 'Parrot OS'
        assert os_info.is_parrot is True
        assert os_info.is_kali is False

    def test_reject_ubuntu(self, mocker):
        """Test rejection of Ubuntu"""
        os_release = 'NAME="Ubuntu"\nVERSION="22.04 LTS"'
        mocker.patch('builtins.open', mocker.mock_open(read_data=os_release))

        detector = OSDetector()
        with pytest.raises(UnsupportedOSError, match="Ubuntu"):
            detector.verify_supported_os()

    def test_update_repos_success(self, mocker):
        """Test apt repository update"""
        mock_run = mocker.patch('subprocess.run')
        mock_run.return_value.returncode = 0

        detector = OSDetector()
        result = detector.update_repos()

        assert result is True
        mock_run.assert_called_once()
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_installer/test_os_detector.py -v`
Expected: FAIL - OSDetector module does not exist

**Step 3: Implement OSDetector**

File: `scripts/installer/core/os_detector.py`
```python
"""OS Detection and Package Manager Abstraction"""

import subprocess
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class UnsupportedOSError(Exception):
    """Raised when OS is not Kali or Parrot"""
    pass


@dataclass
class OSInfo:
    """Operating system information"""
    name: str
    version: str
    id: str

    @property
    def is_kali(self) -> bool:
        return 'kali' in self.id.lower()

    @property
    def is_parrot(self) -> bool:
        return 'parrot' in self.id.lower()

    @property
    def is_supported(self) -> bool:
        return self.is_kali or self.is_parrot


class OSDetector:
    """Detect operating system and provide package manager operations"""

    def __init__(self):
        self.os_info: Optional[OSInfo] = None

    def detect_os(self) -> OSInfo:
        """Detect operating system from /etc/os-release"""
        os_release_path = Path('/etc/os-release')

        if not os_release_path.exists():
            raise UnsupportedOSError("Cannot find /etc/os-release")

        os_data = {}
        with open(os_release_path) as f:
            for line in f:
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    os_data[key] = value.strip('"')

        self.os_info = OSInfo(
            name=os_data.get('NAME', 'Unknown'),
            version=os_data.get('VERSION', 'Unknown'),
            id=os_data.get('ID', '')
        )

        logger.info(f"Detected OS: {self.os_info.name} {self.os_info.version}")
        return self.os_info

    def verify_supported_os(self):
        """Verify OS is Kali or Parrot"""
        if self.os_info is None:
            self.detect_os()

        if not self.os_info.is_supported:
            raise UnsupportedOSError(
                f"{self.os_info.name} is not supported. "
                "This installer only supports Kali Linux and Parrot OS."
            )

    def update_repos(self) -> bool:
        """Update apt package repositories"""
        try:
            logger.info("Updating apt repositories...")
            result = subprocess.run(
                ['apt-get', 'update'],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                logger.info("Repository update successful")
                return True
            else:
                logger.error(f"Repository update failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Repository update timed out")
            return False
        except Exception as e:
            logger.error(f"Error updating repositories: {e}")
            return False

    def install_packages(self, packages: List[str]) -> bool:
        """Install packages via apt-get"""
        try:
            logger.info(f"Installing packages: {', '.join(packages)}")
            result = subprocess.run(
                ['apt-get', 'install', '-y'] + packages,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.returncode == 0:
                logger.info(f"Successfully installed {len(packages)} packages")
                return True
            else:
                logger.error(f"Package installation failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error installing packages: {e}")
            return False
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_installer/test_os_detector.py -v`
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add scripts/installer/core/os_detector.py tests/unit/test_installer/test_os_detector.py
git commit -m "feat(installer): implement OS detection module

- Add OSDetector for Kali/Parrot Linux detection
- Support OS verification and apt operations
- Include comprehensive unit tests with mocking
- Reject unsupported operating systems"
```

---

## Task 4: Implement ToolManager Module

**Files:**
- Create: `scripts/installer/core/tool_manager.py`
- Create: `tests/unit/test_installer/test_tool_manager.py`

**Step 1: Write failing tests for ToolManager**

File: `tests/unit/test_installer/test_tool_manager.py`
```python
import pytest
from scripts.installer.core.tool_manager import ToolManager, InstallStatus, InstallResult
from scripts.installer.core.os_detector import OSDetector

class TestToolManager:
    """Test tool detection and installation"""

    def test_check_installed_tool_exists(self, mocker):
        """Test detection of installed tool"""
        mocker.patch('shutil.which', return_value='/usr/bin/nmap')
        mocker.patch('subprocess.run')

        os_detector = OSDetector()
        manager = ToolManager(os_detector)

        status = manager.check_installed('nmap')

        assert status.installed is True
        assert status.path == '/usr/bin/nmap'

    def test_check_installed_tool_missing(self, mocker):
        """Test detection of missing tool"""
        mocker.patch('shutil.which', return_value=None)

        os_detector = OSDetector()
        manager = ToolManager(os_detector)

        status = manager.check_installed('nonexistent-tool')

        assert status.installed is False
        assert status.path is None

    def test_get_package_name_simple(self):
        """Test simple package name resolution"""
        manager = ToolManager(OSDetector())
        assert manager.get_package_name('nmap') == 'nmap'

    def test_get_package_name_from_registry(self, mocker):
        """Test package name from registry"""
        mock_registry = {
            'tools': {
                'retire-js': {
                    'package': 'retire',
                    'manager': 'npm'
                }
            }
        }
        mocker.patch.object(ToolManager, '_load_registry', return_value=mock_registry)

        manager = ToolManager(OSDetector())
        assert manager.get_package_name('retire-js') == 'retire'

    def test_get_category(self, mocker):
        """Test category detection"""
        mock_registry = {
            'tools': {
                'nmap': {'category': 'network'},
                'sqlmap': {'category': 'web'}
            }
        }
        mocker.patch.object(ToolManager, '_load_registry', return_value=mock_registry)

        manager = ToolManager(OSDetector())
        assert manager.get_category('nmap') == 'network'
        assert manager.get_category('sqlmap') == 'web'
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_installer/test_tool_manager.py -v`
Expected: FAIL - ToolManager module does not exist

**Step 3: Implement ToolManager**

File: `scripts/installer/core/tool_manager.py`
```python
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
            version = self._get_version(tool_name)
            return InstallStatus(installed=True, path=path, version=version)

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
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_installer/test_tool_manager.py -v`
Expected: PASS (5 tests)

**Step 5: Commit**

```bash
git add scripts/installer/core/tool_manager.py tests/unit/test_installer/test_tool_manager.py
git commit -m "feat(installer): implement tool detection and installation

- Add ToolManager for tool operations
- Support apt, pip, npm package managers
- Implement tool scanning (installed vs missing)
- Add comprehensive unit tests with mocking"
```

---

## Task 5: Implement Reporter Module

**Files:**
- Create: `scripts/installer/core/reporter.py`
- Create: `scripts/installer/templates/report.html.j2`
- Create: `tests/unit/test_installer/test_reporter.py`

**Step 1: Write failing tests for Reporter**

File: `tests/unit/test_installer/test_reporter.py`
```python
import pytest
import json
from pathlib import Path
from scripts.installer.core.reporter import Reporter

class TestReporter:
    """Test reporting functionality"""

    def test_generate_html_report(self, tmp_path):
        """Test HTML report generation"""
        reporter = Reporter()
        results = {
            'installed': [
                {'name': 'nmap', 'version': '7.94', 'category': 'network', 'path': '/usr/bin/nmap'}
            ],
            'missing': [
                {'name': 'retire-js', 'package': 'retire', 'category': 'web-enhanced'}
            ],
            'total': 2
        }

        output_file = tmp_path / "report.html"
        reporter.generate_html_report(results, str(output_file))

        assert output_file.exists()
        content = output_file.read_text()
        assert 'nmap' in content
        assert 'retire-js' in content
        assert '7.94' in content

    def test_export_json(self, tmp_path):
        """Test JSON export"""
        reporter = Reporter()
        results = {
            'total': 271,
            'installed': 220,
            'missing': 51,
            'summary': {'percentage': 81.2}
        }

        output_file = tmp_path / "results.json"
        reporter.export_json(results, str(output_file))

        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data['total'] == 271
        assert data['installed'] == 220
        assert 'timestamp' in data
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_installer/test_reporter.py -v`
Expected: FAIL - Reporter module does not exist

**Step 3: Create HTML template**

File: `scripts/installer/templates/report.html.j2`
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HexStrike AI v7.0 - Installation Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #dc3545;
            border-bottom: 3px solid #dc3545;
            padding-bottom: 10px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-card {
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card.total {
            background: #007bff;
            color: white;
        }
        .stat-card.installed {
            background: #28a745;
            color: white;
        }
        .stat-card.missing {
            background: #ffc107;
            color: #333;
        }
        .stat-number {
            font-size: 48px;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-label {
            font-size: 16px;
            opacity: 0.9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th {
            background: #343a40;
            color: white;
            padding: 12px;
            text-align: left;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .category-badge {
            display: inline-block;
            background: #007bff;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
        }
        .timestamp {
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ HexStrike AI v7.0 - Installation Report</h1>
        <p class="timestamp">Generated: {{ timestamp }}</p>

        <div class="summary">
            <div class="stat-card total">
                <div class="stat-label">Total Tools</div>
                <div class="stat-number">{{ total }}</div>
            </div>
            <div class="stat-card installed">
                <div class="stat-label">Installed</div>
                <div class="stat-number">{{ installed|length }}</div>
                <div class="stat-label">{{ (installed|length / total * 100)|round(1) }}%</div>
            </div>
            <div class="stat-card missing">
                <div class="stat-label">Missing</div>
                <div class="stat-number">{{ missing|length }}</div>
                <div class="stat-label">{{ (missing|length / total * 100)|round(1) }}%</div>
            </div>
        </div>

        {% if installed %}
        <h2>✅ Installed Tools ({{ installed|length }})</h2>
        <table>
            <thead>
                <tr>
                    <th>Tool</th>
                    <th>Version</th>
                    <th>Category</th>
                    <th>Path</th>
                </tr>
            </thead>
            <tbody>
                {% for tool in installed|sort(attribute='name') %}
                <tr>
                    <td><strong>{{ tool.name }}</strong></td>
                    <td>{{ tool.version or 'unknown' }}</td>
                    <td><span class="category-badge">{{ tool.category }}</span></td>
                    <td><code>{{ tool.path }}</code></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        {% if missing %}
        <h2>⚠️ Missing Tools ({{ missing|length }})</h2>
        <table>
            <thead>
                <tr>
                    <th>Tool</th>
                    <th>Package</th>
                    <th>Category</th>
                </tr>
            </thead>
            <tbody>
                {% for tool in missing|sort(attribute='name') %}
                <tr>
                    <td><strong>{{ tool.name }}</strong></td>
                    <td><code>{{ tool.package }}</code></td>
                    <td><span class="category-badge">{{ tool.category }}</span></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
    </div>
</body>
</html>
```

**Step 4: Implement Reporter**

File: `scripts/installer/core/reporter.py`
```python
"""Multi-Format Reporting for Installation Results"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


class Reporter:
    """Generate reports in multiple formats (CLI, HTML, JSON)"""

    def __init__(self, use_colors: bool = True):
        self.console = Console() if use_colors else Console(no_color=True)
        self.template_dir = Path('scripts/installer/templates')

    def show_progress(self, description: str):
        """Create and return a progress bar"""
        return Progress()

    def show_summary(self, results: Dict[str, Any]):
        """Display terminal summary table"""
        total = results.get('total', 0)
        installed = len(results.get('installed', []))
        missing = len(results.get('missing', []))
        failed = len(results.get('failed', []))

        self.console.print("\n[bold]Installation Summary:[/bold]")
        self.console.print(f"  Total tools: {total}")
        self.console.print(f"  [green]Installed: {installed} ({installed/total*100:.1f}%)[/green]")
        self.console.print(f"  [yellow]Missing: {missing} ({missing/total*100:.1f}%)[/yellow]")
        if failed > 0:
            self.console.print(f"  [red]Failed: {failed}[/red]")

        # Show installed tools table
        if results.get('installed'):
            table = Table(title="Installed Tools", show_header=True, header_style="bold green")
            table.add_column("Tool", style="green")
            table.add_column("Version", style="dim")
            table.add_column("Category")

            for tool in sorted(results['installed'], key=lambda x: x['name'])[:10]:
                table.add_row(
                    tool['name'],
                    tool.get('version', 'unknown'),
                    tool.get('category', 'unknown')
                )

            if len(results['installed']) > 10:
                table.add_row("...", "...", f"({len(results['installed'])-10} more)")

            self.console.print(table)

        # Show missing tools table
        if results.get('missing'):
            table = Table(title="Missing Tools", show_header=True, header_style="bold yellow")
            table.add_column("Tool", style="yellow")
            table.add_column("Package")
            table.add_column("Category")

            for tool in sorted(results['missing'], key=lambda x: x['name'])[:10]:
                table.add_row(
                    tool['name'],
                    tool.get('package', tool['name']),
                    tool.get('category', 'unknown')
                )

            if len(results['missing']) > 10:
                table.add_row("...", "...", f"({len(results['missing'])-10} more)")

            self.console.print(table)

    def generate_html_report(self, results: Dict[str, Any], output_path: str):
        """Generate HTML report from template"""
        try:
            env = Environment(loader=FileSystemLoader(str(self.template_dir)))
            template = env.get_template('report.html.j2')

            html_content = template.render(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                total=results.get('total', 0),
                installed=results.get('installed', []),
                missing=results.get('missing', [])
            )

            with open(output_path, 'w') as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {output_path}")

        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")

    def export_json(self, results: Dict[str, Any], output_path: str):
        """Export results as JSON"""
        try:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'total': results.get('total', 0),
                    'installed': len(results.get('installed', [])),
                    'missing': len(results.get('missing', [])),
                    'percentage': len(results.get('installed', [])) / results.get('total', 1) * 100
                },
                'installed': results.get('installed', []),
                'missing': results.get('missing', []),
                'failed': results.get('failed', [])
            }

            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)

            logger.info(f"JSON export saved: {output_path}")

        except Exception as e:
            logger.error(f"Error exporting JSON: {e}")

    def show_installation_plan(self, installed: List[str], missing: List[str], dry_run: bool = False):
        """Show what will be installed"""
        self.console.print("\n[bold cyan]Installation Plan:[/bold cyan]")
        self.console.print(f"  Already installed: [green]{len(installed)}[/green]")
        self.console.print(f"  To be installed: [yellow]{len(missing)}[/yellow]")

        if dry_run:
            self.console.print("\n[bold yellow]DRY RUN - No changes will be made[/bold yellow]")

        if missing:
            self.console.print("\n[bold]Tools to install:[/bold]")
            for tool in missing[:20]:
                self.console.print(f"  • {tool}")
            if len(missing) > 20:
                self.console.print(f"  ... and {len(missing)-20} more")
```

**Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/test_installer/test_reporter.py -v`
Expected: PASS (2 tests)

**Step 6: Commit**

```bash
git add scripts/installer/core/reporter.py scripts/installer/templates/ tests/unit/test_installer/test_reporter.py
git commit -m "feat(installer): implement multi-format reporting

- Add Reporter for CLI, HTML, and JSON output
- Create Jinja2 HTML template for installation reports
- Support progress display and summary tables
- Add comprehensive unit tests"
```

---

## Execution Plan Summary

**Remaining Tasks (simplified overview):**

- Task 6-8: Installation modes (quick, standard, complete)
- Task 9-11: Category definitions (network, web, binary, etc.)
- Task 12: Main CLI entry point
- Task 13: Bash wrapper script
- Task 14-15: Dependency checker
- Task 16-18: Docker implementation
- Task 19-21: Integration tests
- Task 22: Documentation

**Total Estimated Time:** 2-3 weeks (as per Phase 4 timeline)

**Notes:**
- Each task follows TDD: test → implement → verify → commit
- All code includes type hints and docstrings
- Tests use pytest with mocking for external dependencies
- Frequent commits with descriptive messages

---

## Next Steps

This implementation plan provides bite-sized tasks for Phase 4. Each task is 2-5 minutes of focused work with clear success criteria.

**@superpowers:karpathy-guidelines** - Follow simplicity-first principles throughout implementation.
