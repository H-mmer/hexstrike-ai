#!/usr/bin/env python3
"""
HexStrike AI — Server Entry Point

Starts the Flask API server that exposes 200+ security tools
and AI agents via REST API.

Usage:
    python3 hexstrike_server.py
    python3 hexstrike_server.py --debug
    python3 hexstrike_server.py --port 9000
"""
import argparse
import logging
from core.server import create_app
from core.constants import API_PORT, API_HOST
from utils.logger import setup_basic_logging

logger = setup_basic_logging()


def parse_args():
    parser = argparse.ArgumentParser(description="Run the HexStrike AI API Server")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--port", type=int, default=API_PORT)
    return parser.parse_args()


def main():
    args = parse_args()
    logger.info("Starting HexStrike AI API Server")
    app = create_app()
    logger.info(f"Starting HexStrike AI on port {args.port}")
    app.run(host=API_HOST, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
