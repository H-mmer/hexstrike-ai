#!/usr/bin/env python3
"""
HexStrike AI - Configuration Constants

Central configuration for all HexStrike components.
"""

import os

# ============================================================================
# API SERVER CONFIGURATION
# ============================================================================

API_PORT = int(os.environ.get('HEXSTRIKE_PORT', 8888))
API_HOST = os.environ.get('HEXSTRIKE_HOST', '127.0.0.1')

# ============================================================================
# EXECUTION CONFIGURATION
# ============================================================================

DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 300  # 5 minutes default timeout

# ============================================================================
# CACHE CONFIGURATION
# ============================================================================

CACHE_SIZE = 1000
CACHE_TTL = 3600  # 1 hour

# ============================================================================
# TOOL TIMEOUTS (seconds)
# ============================================================================

# Network scanning timeouts
NMAP_TIMEOUT = 600
MASSCAN_TIMEOUT = 300
RUSTSCAN_TIMEOUT = 180

# Web scanning timeouts
GOBUSTER_TIMEOUT = 600
FFUF_TIMEOUT = 600
NUCLEI_TIMEOUT = 900

# Exploitation timeouts
SQLMAP_TIMEOUT = 1200
METASPLOIT_TIMEOUT = 900

# Default timeout for unknown tools
DEFAULT_TOOL_TIMEOUT = 300
