# Phase 4: Installation & Docker Infrastructure - Design Document

**Date:** 2026-02-17
**Status:** Approved
**Target:** HexStrike AI v7.0
**Objective:** Reduce installation time from 45+ minutes to 3-15 minutes

---

## Executive Summary

Phase 4 transforms HexStrike AI deployment through automated installation and Docker containerization. The hybrid approach combines a lightweight bash wrapper with Python core modules to provide professional pentesters on Kali/Parrot with flexible, reliable installation of 271 security tools across multiple categories.

**Key Goals:**
- **Installation Time:** 45 min → 3-15 min (depending on mode)
- **Success Rate:** 70% → 95%
- **Target OS:** Kali Linux and Parrot OS
- **Optional Database:** PostgreSQL support for persistence
- **Docker Images:** 3 variants (minimal, standard, full)

---

## 1. Overall Architecture

### High-Level Structure

```
hexstrike-ai/
├── scripts/
│   ├── install.sh                 # Entry point (bash wrapper)
│   ├── check_deps.py              # Standalone dependency checker
│   └── installer/                 # Python installation framework
│       ├── __init__.py
│       ├── core/                  # Shared modules
│       │   ├── tool_manager.py    # Tool detection & installation
│       │   ├── os_detector.py     # OS detection
│       │   └── reporter.py        # Multi-format reporting
│       ├── modes/                 # Installation presets
│       │   ├── quick.py           # 50 essential tools
│       │   ├── standard.py        # 150 core tools
│       │   └── complete.py        # All 271 tools
│       ├── categories/            # Tool categories
│       │   ├── web.py
│       │   ├── network.py
│       │   ├── binary.py
│       │   └── ...
│       └── main.py                # CLI entry point
├── docker/
│   ├── Dockerfile                 # Multi-stage build
│   ├── docker-compose.yml         # With PostgreSQL
│   ├── docker-compose.simple.yml  # Standalone
│   └── .dockerignore
├── requirements.txt               # Python dependencies
└── requirements-dev.txt           # Testing dependencies
```

### Design Principles

1. **Single Entry Point** - One command: `./scripts/install.sh [mode]`
2. **Shared Logic** - Python modules reused by installer, Docker, and checker
3. **Kali/Parrot Optimized** - Leverages apt + Kali repos
4. **Smart Detection** - Skips already-installed tools
5. **Professional Focus** - Reliability over minimal size
6. **Optional Database** - Works standalone or with PostgreSQL

### Installation Flow

```
User runs install.sh
    ↓
Bash: Detect OS (must be Kali/Parrot)
    ↓
Bash: Create venv, install core Python deps
    ↓
Python: Parse mode/categories, scan installed tools
    ↓
Python: Install missing tools (prioritized by tier)
    ↓
Python: Verify installation, generate reports
    ↓
Success! Server ready to start
```

---

## 2. Installation Script (install.sh)

### Command-Line Interface

```bash
# Interactive mode (prompts for choices)
./scripts/install.sh

# Quick mode (50 essential tools, ~5 minutes)
./scripts/install.sh --mode quick

# Standard mode (150 core tools, ~15 minutes)
./scripts/install.sh --mode standard

# Complete mode (all 271 tools, ~30 minutes)
./scripts/install.sh --mode complete

# Custom categories
./scripts/install.sh --categories web,network,binary

# Dry-run (show what would be installed)
./scripts/install.sh --mode standard --dry-run
```

### Bash Wrapper Responsibilities

1. **OS Detection** - Verify Kali Linux or Parrot OS (exit with error if wrong OS)
2. **Prerequisite Check** - Ensure Python 3.8+, apt, git available
3. **Virtual Environment** - Create `hexstrike-env/` if needed
4. **Core Dependencies** - Install click, rich, requests, pyyaml
5. **Delegate to Python** - Call `python -m scripts.installer.main` with arguments
6. **Report Results** - Display summary and next steps

### Script Structure

```bash
#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, pipe failures

# 1. OS Detection
if ! grep -q "Kali\|Parrot" /etc/os-release; then
    echo "ERROR: This installer only supports Kali Linux and Parrot OS"
    exit 1
fi

# 2. Prerequisite checks
command -v python3 >/dev/null || { echo "Python 3 required"; exit 1; }
command -v apt-get >/dev/null || { echo "apt-get required"; exit 1; }

# 3. Create/activate venv
[ ! -d "hexstrike-env" ] && python3 -m venv hexstrike-env
source hexstrike-env/bin/activate

# 4. Install minimal installer dependencies
pip install -q click rich requests pyyaml

# 5. Delegate to Python installer
python -m scripts.installer.main "$@"

# 6. Show next steps
echo "✅ Installation complete! Run: python3 hexstrike_server.py"
```

### Error Handling

- **Wrong OS** → Clear error with Docker alternative link
- **Missing prerequisites** → Show exact installation commands
- **Python errors** → Re-install core dependencies
- **Network issues** → Suggest offline mode or retry

---

## 3. Python Core Modules

### tool_manager.py - Tool Detection & Installation

```python
class ToolManager:
    """Manages detection and installation of security tools"""

    def __init__(self, os_detector: OSDetector):
        self.os = os_detector
        self.tool_registry = self._load_tool_registry()

    def check_installed(self, tool_name: str) -> InstallStatus:
        """Check if tool is already installed"""
        # 1. Check with 'which' command
        # 2. Check package manager (dpkg -l)
        # 3. Check version output (tool --version)

    def install_tool(self, tool_name: str) -> InstallResult:
        """Install single tool via package manager"""
        # 1. Resolve package name
        # 2. Try apt-get install
        # 3. Fall back to pip/npm/cargo if needed
        # 4. Return detailed result

    def install_batch(self, tools: List[str], progress_callback) -> BatchResult:
        """Install multiple tools with progress reporting"""
        # Smart batching by package manager
        # Continue on individual failures
```

**Tool Registry** (`scripts/installer/registry.yaml`):

```yaml
tools:
  nmap:
    package: nmap
    manager: apt
    category: network
    tier: essential

  retire-js:
    package: retire.js
    manager: npm
    category: web-enhanced
    tier: specialized

  rizin:
    package: rizin
    manager: apt
    category: binary-enhanced
    tier: core
    alternatives: [radare2]
```

### os_detector.py - OS Detection

```python
class OSDetector:
    """Detect OS and provide package manager abstraction"""

    def detect_os(self) -> OSInfo:
        """Detect Kali vs Parrot and version"""
        # Parse /etc/os-release
        return OSInfo(name="Kali", version="2024.2")

    def update_repos(self):
        """Update apt repositories"""
        # apt-get update with error handling

    def install_packages(self, packages: List[str]) -> InstallResult:
        """Install via apt-get"""
        # Batch installation with error parsing
```

### reporter.py - Multi-Format Reporting

```python
class Reporter:
    """Generate CLI output, HTML reports, and JSON exports"""

    def show_progress(self, current: int, total: int, tool: str):
        """Live progress bar with current tool"""
        # Rich progress bar with spinners

    def show_summary(self, results: InstallResults):
        """Terminal table: installed/failed/skipped"""
        # Color-coded Rich table

    def generate_html_report(self, results: InstallResults, path: str):
        """Generate styled HTML report"""
        # Summary stats, per-category breakdown, error details

    def export_json(self, results: InstallResults, path: str):
        """Export machine-readable JSON"""
        # For CI/CD integration
```

### main.py - CLI Entry Point

```python
@click.command()
@click.option('--mode', type=click.Choice(['quick', 'standard', 'complete']))
@click.option('--categories', help='Comma-separated categories')
@click.option('--dry-run', is_flag=True)
def main(mode, categories, dry_run):
    """HexStrike AI Installation Manager"""
    # 1. Detect OS
    # 2. Initialize managers
    # 3. Determine tool list
    # 4. Scan installed tools (smart detection)
    # 5. Show installation plan
    # 6. Install missing tools (if not dry-run)
    # 7. Generate reports (CLI + HTML + JSON)
```

---

## 4. Installation Modes & Categories

### Predefined Modes

**Quick Mode** (~5 minutes, 50 essential tools):
- Network: nmap, rustscan, masscan, amass, subfinder
- Web: gobuster, nuclei, httpx, sqlmap, nikto
- Binary: gdb, radare2, ghidra, checksec, strings
- Cloud: trivy, scout-suite
- Auth: hydra, john, hashcat

**Standard Mode** (~15 minutes, 150 core tools):
- All Quick tools plus:
- Network: autorecon, dnsenum, fierce, theharvester
- Web: feroxbuster, ffuf, wpscan, arjun, katana, dalfox
- Mobile: apktool, jadx, mobsf, frida (Phase 2)
- API: kiterunner, jwt-hack, swagger-scanner (Phase 2)
- Wireless: wifite2, bettercap, airgeddon (Phase 2)

**Complete Mode** (~30 minutes, all 271 tools):
- All tools from Phases 1-3
- Enhanced web tools (Phase 3)
- Enhanced network/cloud tools (Phase 3)
- Enhanced binary/forensics tools (Phase 3)

### Tool Categories

Aligned with Phase 1-3 modular structure:

- **network** (25+ tools, essential tier)
- **web** (40+ tools, essential tier)
- **web-enhanced** (30 Phase 3 tools, specialized tier)
- **binary** (25+ tools, core tier)
- **binary-enhanced** (8 Phase 3 tools, specialized tier)
- **mobile** (20 Phase 2 tools, specialized tier)
- **api** (15 Phase 2 tools, core tier)
- **wireless** (15 Phase 2 tools, specialized tier)
- **cloud** (20+ tools, core tier)
- **forensics** (20+ tools, specialized tier)
- **malware** (6 Phase 3 tools, specialized tier)
- **osint** (20+ tools, core tier)

### Tiered Installation

```python
TIERS = {
    'essential': {'priority': 1, 'install_time': '2-3 min'},
    'core': {'priority': 2, 'install_time': '5-10 min'},
    'specialized': {'priority': 3, 'install_time': '10-20 min'},
    'experimental': {'priority': 4, 'install_time': 'varies'}
}
```

Installation order: essential → core → specialized → experimental

### Smart Detection

```python
def get_tools_to_install(mode, categories, skip_installed=True):
    # 1. Start with mode preset
    # 2. Override with categories if specified
    # 3. Filter already-installed tools
    # 4. Sort by tier priority
    return tools
```

---

## 5. Docker Implementation

### Multi-Stage Dockerfile

```dockerfile
# Stage 1: Base Python environment
FROM kalilinux/kali-rolling:latest AS base
RUN apt-get update && apt-get install -y python3 python3-pip git
WORKDIR /opt/hexstrike-ai
COPY requirements.txt .
RUN python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt

# Stage 2: Minimal variant (50 essential tools)
FROM base AS minimal
COPY scripts/ tools/ agents/ managers/ core/ utils/ ./
RUN . venv/bin/activate && python -m scripts.installer.main --mode quick
COPY hexstrike_server.py hexstrike_mcp.py ./
EXPOSE 8888
CMD ["bash", "-c", "source venv/bin/activate && python3 hexstrike_server.py"]

# Stage 3: Standard variant (150 core tools)
FROM base AS standard
COPY scripts/ tools/ agents/ managers/ core/ utils/ ./
RUN . venv/bin/activate && python -m scripts.installer.main --mode standard
COPY hexstrike_server.py hexstrike_mcp.py ./
EXPOSE 8888
CMD ["bash", "-c", "source venv/bin/activate && python3 hexstrike_server.py"]

# Stage 4: Full variant (all 271 tools)
FROM base AS full
COPY scripts/ tools/ agents/ managers/ core/ utils/ ./
RUN . venv/bin/activate && python -m scripts.installer.main --mode complete
COPY hexstrike_server.py hexstrike_mcp.py ./
EXPOSE 8888
CMD ["bash", "-c", "source venv/bin/activate && python3 hexstrike_server.py"]
```

### Docker Image Variants

| Variant | Size | Tools | Use Case |
|---------|------|-------|----------|
| hexstrike/ai:v7.0-minimal | ~2GB | 50 essential | Quick demos, basic testing |
| hexstrike/ai:v7.0-standard | ~5GB | 150 core | Most pentest scenarios |
| hexstrike/ai:v7.0-full | ~10GB | All 271 | Comprehensive assessments |

### Docker Compose

**With Database** (`docker-compose.yml`):
```yaml
services:
  hexstrike:
    image: hexstrike/ai:v7.0-standard
    ports: ["8888:8888"]
    volumes:
      - ./results:/opt/hexstrike-ai/results
    environment:
      - DATABASE_URL=postgresql://hexstrike:password@postgres:5432/hexstrike
    depends_on: [postgres]

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=hexstrike
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    profiles: [with-db]
```

**Simple** (`docker-compose.simple.yml`):
```yaml
services:
  hexstrike:
    image: hexstrike/ai:v7.0-standard
    ports: ["8888:8888"]
    volumes:
      - ./results:/opt/hexstrike-ai/results
```

### Usage Examples

```bash
# Quick demo
docker run -p 8888:8888 hexstrike/ai:v7.0-minimal

# With database
docker-compose --profile with-db up -d

# Isolated testing
docker run -p 9000:8888 --name test-instance hexstrike/ai:v7.0-standard

# Persistent results
docker run -p 8888:8888 -v $(pwd)/results:/opt/hexstrike-ai/results hexstrike/ai:v7.0-full
```

---

## 6. Dependency Checker

### CLI Interface

```bash
# Check all tools
./scripts/check_deps.py

# Check specific categories
./scripts/check_deps.py --categories web,network

# Export HTML report
./scripts/check_deps.py --html report.html

# Export JSON (CI/CD)
./scripts/check_deps.py --json deps.json

# Show installation commands
./scripts/check_deps.py --show-install-cmds

# Quiet mode (exit code only)
./scripts/check_deps.py --quiet
```

### Output Formats

**CLI Output** (Rich tables with colors):
- Summary: total/installed/missing with percentages
- Installed tools: name, version, category, path
- Missing tools: name, package, category
- Installation commands grouped by category

**HTML Report**:
- Summary stats with pie chart
- Per-category breakdown
- Failed installations with error details
- System information

**JSON Export**:
```json
{
  "timestamp": "2026-02-17T10:30:00Z",
  "summary": {"total": 271, "installed": 220, "missing": 51},
  "installed": [{"name": "nmap", "version": "7.94", "category": "network"}],
  "missing": [{"name": "retire-js", "package": "retire.js", "category": "web-enhanced"}]
}
```

### Integration with Installer

The installer automatically runs dependency checker before installation to show users exactly what will be installed.

---

## 7. Error Handling & Recovery

### Network Failures

```python
def install_with_retry(package, max_retries=3):
    # Exponential backoff: 1s, 2s, 4s
    # Offer offline alternatives if available
    # Continue with other tools on final failure
```

### Package Manager Errors

- **Package not found** → Try alternatives, suggest manual installation
- **dpkg interrupted** → Auto-fix with `dpkg --configure -a`, retry
- **Lock held** → Wait and suggest retry
- **Unknown errors** → Log details, continue with other tools

### Tool-Specific Failures

Multi-strategy installation:
1. apt-get (Kali repository)
2. Alternative package managers (npm, pip, cargo)
3. Build from source
4. Manual installation guide

### Continue-on-Error

Installation continues even if individual tools fail. Failures are collected and reported at the end with suggestions.

### User-Friendly Error Messages

```
❌ Network Error

Could not download packages. Please check:
- Internet connection is active
- DNS resolution working (ping google.com)
- apt repositories configured (apt-get update)

Retry with: ./scripts/install.sh --mode {mode}
```

### Comprehensive Logging

- **Console**: INFO level with colors
- **File**: DEBUG level with rotation (`install.log`, 10MB max, 5 backups)
- All commands and results logged for debugging

### Recovery Commands

```bash
# Check detailed logs
cat install.log | grep ERROR

# Retry failed installations
./scripts/install.sh --retry-failed

# Continue from last failure
./scripts/install.sh --resume

# Clean and restart
./scripts/install.sh --clean --mode standard
```

---

## 8. Testing Strategy

### Unit Tests (90%+ coverage target)

**Core modules** (`tests/unit/test_installer/`):
- `test_tool_manager.py` - Tool detection, package resolution, category mapping
- `test_os_detector.py` - OS detection, Kali/Parrot verification
- `test_reporter.py` - HTML/JSON generation, CLI formatting

### Integration Tests

**Installation process** (`tests/integration/`):
- Quick/standard/complete mode installations
- Category-based installations
- Dependency checker accuracy
- Error handling scenarios

### Docker Build Tests

**Image builds** (`tests/integration/test_docker.py`):
- Minimal/standard/full image builds
- Container startup and health checks
- Docker Compose configurations

### End-to-End Tests

**Full workflow** (`tests/e2e/`):
- Fresh installation → start server → verify tools work
- Installation resume after failure
- Database integration (optional)

### CI/CD Integration

GitHub Actions workflow:
- Unit tests on every push
- Docker build tests
- Integration tests on Kali container
- Coverage reporting

### Test Execution

```bash
# All tests
pytest

# Fast tests only (skip slow integration)
pytest -m "not slow"

# With coverage
pytest --cov=scripts/installer --cov-report=html

# Docker tests
pytest -m docker

# E2E tests
pytest -m e2e
```

---

## Success Criteria

- ✅ Installation time: 45 min → 3-15 min (depending on mode)
- ✅ Installation success rate: 70% → 95%
- ✅ One-command native installation working on Kali/Parrot
- ✅ Docker images built and tested (minimal, standard, full)
- ✅ Dependency checker provides accurate reports (CLI + HTML + JSON)
- ✅ Error handling provides clear recovery paths
- ✅ Test coverage ≥85% for installer modules
- ✅ Documentation complete with usage examples

---

## Next Steps

This approved design will be implemented following the detailed implementation plan to be created using the `writing-plans` skill.

**Estimated Implementation Time:** 2-3 weeks (Weeks 13-14 per V7 plan)

**Implementation Order:**
1. Core Python modules (tool_manager, os_detector, reporter)
2. Installation modes and category system
3. Bash wrapper script
4. Dependency checker
5. Docker implementation
6. Testing infrastructure
7. Documentation and examples
