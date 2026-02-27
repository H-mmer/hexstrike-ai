# core/validation.py
"""Shared input validation for target parameters.

Provides validators for different field categories:
- is_valid_target(): IPs, domains, CIDRs, URLs (for `target`, `host`, `target_network`)
- is_valid_domain(): Domain/subdomain only (for `domain` params)
- sanitize_additional_args(): Reject shell metacharacters in free-form args
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

# Shell metacharacters that should never appear in a target string
_SHELL_METACHARS = re.compile(r"[;|&`$\n\r]")

# Loose domain regex: labels separated by dots, optional trailing port
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}(?::\d{1,5})?$"
)

# URL with scheme
_URL_RE = re.compile(r"^https?://\S+$")


def is_valid_target(target: str) -> bool:
    """Return True if *target* looks like a valid IP, domain, CIDR, or URL.

    Rejects empty strings and strings containing shell metacharacters.
    URLs are checked FIRST (before metachar rejection) because URL query
    strings legitimately contain & and = which are shell metachars.
    Use for: target, host, target_network, url params.
    """
    if not target or not target.strip():
        return False

    target = target.strip()

    # URL — check first because query params may contain & = etc.
    if _URL_RE.match(target):
        return True

    # Non-URL targets: reject shell metacharacters
    if _SHELL_METACHARS.search(target):
        return False

    # CIDR
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass

    # IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Domain
    if _DOMAIN_RE.match(target):
        return True

    return False


def is_valid_domain(domain: str) -> bool:
    """Return True if *domain* is a valid domain/subdomain (no IPs, no CIDRs).

    Use for: domain params in bugbounty, osint routes.
    """
    if not domain or not domain.strip():
        return False
    domain = domain.strip()
    if _SHELL_METACHARS.search(domain):
        return False
    return bool(_DOMAIN_RE.match(domain))


def sanitize_additional_args(args: str) -> Optional[str]:
    """Return *args* if safe (no shell metacharacters), else None.

    Use for: additional_args, flags, nse_scripts params.
    Empty string is considered safe.
    """
    if not args:
        return args  # "" or None pass through
    if _SHELL_METACHARS.search(args):
        return None
    return args
