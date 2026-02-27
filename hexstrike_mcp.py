#!/usr/bin/env python3
"""
HexStrike AI MCP Client — Entry Point

Connects to the HexStrike AI API server and exposes all security tools
to AI agents via the Model Context Protocol (MCP).

Usage:
    python3 hexstrike_mcp.py --server http://localhost:8888
    python3 hexstrike_mcp.py --server http://localhost:8888 --debug
"""
import argparse
import logging

from hexstrike_mcp_tools.client import HexStrikeClient, DEFAULT_HEXSTRIKE_SERVER, DEFAULT_REQUEST_TIMEOUT
import hexstrike_mcp_tools
import hexstrike_mcp_tools.system
import hexstrike_mcp_tools.network
import hexstrike_mcp_tools.web
import hexstrike_mcp_tools.cloud
import hexstrike_mcp_tools.binary
import hexstrike_mcp_tools.mobile
import hexstrike_mcp_tools.api_security
import hexstrike_mcp_tools.wireless
import hexstrike_mcp_tools.osint
import hexstrike_mcp_tools.workflows
import hexstrike_mcp_tools.async_tools
import hexstrike_mcp_tools.browser

logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="Run the HexStrike AI MCP Client")
    parser.add_argument("--server", default=DEFAULT_HEXSTRIKE_SERVER)
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT)
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    client = HexStrikeClient(args.server, args.timeout)
    hexstrike_mcp_tools.initialize(client)
    hexstrike_mcp_tools.mcp.run()


if __name__ == "__main__":
    main()
