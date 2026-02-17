#!/usr/bin/env bash
#
# HexStrike AI Installer - Bash Wrapper Script
#
# Provides convenient CLI interface for the Python installer.
# Automatically activates virtual environment if available.
#
# Usage:
#   ./install.sh --mode quick
#   ./install.sh --mode standard --dry-run
#   ./install.sh --categories network,web
#

set -e  # Exit on error

# Get script directory (absolute path)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Change to project root
cd "$PROJECT_ROOT"

# Color output functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if virtual environment exists and activate it
if [ -d "hexstrike-env" ]; then
    info "Activating virtual environment..."
    source hexstrike-env/bin/activate
elif [ -d "venv" ]; then
    info "Activating virtual environment..."
    source venv/bin/activate
else
    warn "No virtual environment found. Using system Python."
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]; }; then
    error "Python 3.8+ required. Found: $PYTHON_VERSION"
    exit 1
fi

# Check if Click is installed (required dependency)
if ! python3 -c "import click" 2>/dev/null; then
    error "Required dependency 'click' not installed."
    echo "Please install dependencies: pip3 install -r requirements.txt"
    exit 1
fi

# Run the Python installer module
info "Starting HexStrike AI Installer..."
python3 -m scripts.installer.main "$@"
EXIT_CODE=$?

# Handle exit codes
if [ $EXIT_CODE -eq 0 ]; then
    info "Installer completed successfully."
elif [ $EXIT_CODE -eq 130 ]; then
    warn "Installation cancelled by user."
else
    error "Installer exited with error code: $EXIT_CODE"
fi

exit $EXIT_CODE
