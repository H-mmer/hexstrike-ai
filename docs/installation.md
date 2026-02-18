# HexStrike AI — Installation Guide

## Quick Start (3 Steps)

```bash
# 1. Clone the repository
git clone https://github.com/0x4m4/hexstrike-ai.git
cd hexstrike-ai

# 2. Set up Python environment
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate
pip3 install -r requirements.txt

# 3. Install security tools (choose a mode)
bash scripts/installer/install.sh --mode quick     # 25 essential tools, ~5 min
bash scripts/installer/install.sh --mode standard  # 64 tools, ~15 min
bash scripts/installer/install.sh --mode complete  # 105 tools, ~30 min
```

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.8+ | Required |
| pip | Any | Usually bundled with Python |
| git | Any | For cloning the repository |
| OS | Kali Linux / Parrot OS | Other Debian-based may work |
| Disk Space | 5 GB+ | For tool installations |
| Internet | Required | For downloading tools |

### Check Prerequisites

```bash
python3 --version   # Should be 3.8+
pip3 --version
git --version
df -h /             # Check available disk space
```

---

## Installation Modes

The installer offers three modes targeting different use cases:

| Mode | Tools | Time | Best For |
|------|-------|------|----------|
| **quick** | 25 (essential tier) | ~5 min | CTF competitions, rapid testing |
| **standard** | 64 (essential + core) | ~15 min | Bug bounty, standard pentests |
| **complete** | 105 (all tiers) | ~30 min | Comprehensive security labs |

### Mode Examples

```bash
# Quick mode — 25 essential tools
python3 -m scripts.installer.main --mode quick

# Standard mode — 64 tools
python3 -m scripts.installer.main --mode standard

# Complete mode — all 105 tools
python3 -m scripts.installer.main --mode complete

# Preview what would be installed (no changes made)
python3 -m scripts.installer.main --mode quick --dry-run
```

---

## Category Reference

Install only the tools you need by specifying categories:

| Category | Tools | Description |
|----------|-------|-------------|
| **network** | 25 | Nmap, rustscan, masscan, amass, subfinder, nuclei, etc. |
| **web** | 30 | Gobuster, ffuf, sqlmap, nikto, nuclei, burpsuite, etc. |
| **cloud** | 10 | Trivy, prowler, scout-suite, kube-hunter, pacu, etc. |
| **binary** | 15 | GDB, ghidra, radare2, binwalk, checksec, pwndbg, etc. |
| **mobile** | 8 | Apktool, jadx, mobsf, frida, androguard, etc. |
| **forensics** | 8 | Yara, volatility3, autopsy, sleuthkit, bulk-extractor, etc. |

### Category Examples

```bash
# Install network tools only
python3 -m scripts.installer.main --categories network

# Install web and cloud tools
python3 -m scripts.installer.main --categories web,cloud

# Standard mode + specific categories
python3 -m scripts.installer.main --mode standard --categories network,binary

# Dry run to preview category selection
python3 -m scripts.installer.main --categories mobile --dry-run
```

---

## CLI Reference

```
usage: python3 -m scripts.installer.main [OPTIONS]

Options:
  --mode [quick|standard|complete]   Installation mode (default: quick)
  --categories TEXT                  Comma-separated category list
                                     (network,web,cloud,binary,mobile,forensics)
  --dry-run                          Preview tools without installing
  --output [terminal|html|json]      Report format (default: terminal)
  --skip-checks                      Skip pre-flight dependency validation
  --help                             Show this message and exit
```

### Common Workflows

```bash
# Dry run to preview everything
python3 -m scripts.installer.main --mode complete --dry-run

# Install and generate HTML report
python3 -m scripts.installer.main --mode standard --output html

# Install and export JSON report (for CI/CD)
python3 -m scripts.installer.main --mode quick --output json

# Skip pre-flight checks (advanced users)
python3 -m scripts.installer.main --mode standard --skip-checks

# Combined: categories + report
python3 -m scripts.installer.main --categories web,cloud --output html
```

---

## Bash Wrapper

The bash wrapper at `scripts/installer/install.sh` provides a convenient entry point:

```bash
# Make executable (first time only)
chmod +x scripts/installer/install.sh

# Use identically to the Python CLI
bash scripts/installer/install.sh --mode quick
bash scripts/installer/install.sh --mode standard --dry-run
bash scripts/installer/install.sh --categories network,web
```

The wrapper automatically:
- Activates the virtual environment if found
- Validates Python 3.8+ is available
- Checks that `click` is installed
- Passes all arguments to the main installer

---

## Docker Installation

HexStrike AI provides Docker images for each installation mode:

### Using Docker Compose

```bash
# Quick mode (port 8888)
docker-compose up hexstrike-quick

# Standard mode (port 8889)
docker-compose up hexstrike-standard

# Complete mode (port 8890)
docker-compose up hexstrike-complete
```

### Using Docker CLI

```bash
# Build quick mode image
docker build --target quick-mode -t hexstrike-quick .

# Run
docker run -p 8888:8888 hexstrike-quick
```

See [scripts/installer/DOCKER.md](../scripts/installer/DOCKER.md) for the full Docker guide.

---

## Verifying Installation

```bash
# Check installed tools
python3 -m scripts.installer.main --mode quick --dry-run

# Test the HexStrike server
python3 hexstrike_server.py
curl http://localhost:8888/health
```

---

## Troubleshooting

### "Unsupported OS" Error

The installer currently supports **Kali Linux** and **Parrot OS**.
On other Debian-based systems, use `--skip-checks` to bypass OS detection:

```bash
python3 -m scripts.installer.main --mode quick --skip-checks
```

### "No module named 'click'" Error

Install Python dependencies first:

```bash
pip3 install -r requirements.txt
```

### Tool Installation Failures

Some tools may fail to install (network errors, missing repositories). The installer
continues on individual failures and reports a final summary. Re-run with `--dry-run`
to see which tools are missing, then install them manually.

### Disk Space Issues

The complete mode requires ~5 GB. Check available space:

```bash
df -h /
```

---

## Adding New Tools

To add a tool to the registry:

1. Edit `scripts/installer/registry.yaml`:
   ```yaml
   tool-name:
     package: package-name
     manager: apt          # or pip, npm
     category: network     # network|web|cloud|binary|mobile|forensics
     tier: core            # essential|core|specialized
     description: "Brief description"
   ```

2. Run the smoke test:
   ```bash
   python3 -m scripts.installer.main --categories network --dry-run
   ```

3. Run the test suite:
   ```bash
   pytest tests/unit/test_installer/ -v
   ```
