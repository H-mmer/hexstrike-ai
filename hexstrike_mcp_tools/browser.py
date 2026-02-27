# hexstrike_mcp_tools/browser.py
"""MCP tools: stealth browser agent."""
from typing import Optional
from hexstrike_mcp_tools import get_client


def browser_navigate(url: str, preset: str = "standard", wait: float = 2.0) -> str:
    """Navigate to a URL using stealth browser. Returns DOM metadata."""
    return get_client().safe_post(
        "/api/browser/navigate",
        {"url": url, "preset": preset, "wait": wait},
    )


def browser_screenshot(url: str, preset: str = "standard") -> str:
    """Navigate to URL and return base64-encoded screenshot."""
    return get_client().safe_post(
        "/api/browser/screenshot",
        {"url": url, "preset": preset},
    )


def browser_extract_dom(url: str, preset: str = "standard") -> str:
    """Extract DOM structure, links, and form count from a URL."""
    return get_client().safe_post(
        "/api/browser/dom",
        {"url": url, "preset": preset},
    )


def browser_form_fill(url: str, selector: str, value: str, preset: str = "standard") -> str:
    """Fill a form field with value using stealth typing."""
    return get_client().safe_post(
        "/api/browser/form-fill",
        {"url": url, "selector": selector, "value": value, "preset": preset},
    )
