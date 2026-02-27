# tests/unit/test_validation.py
"""Tests for target input validation."""
from core.validation import is_valid_target, is_valid_domain, sanitize_additional_args


# --- is_valid_target (IP / domain / CIDR / URL) ---

def test_valid_ipv4():
    assert is_valid_target("192.168.1.1") is True

def test_valid_ipv6():
    assert is_valid_target("::1") is True

def test_valid_domain():
    assert is_valid_target("example.com") is True

def test_valid_subdomain():
    assert is_valid_target("sub.example.com") is True

def test_valid_cidr():
    assert is_valid_target("10.0.0.0/24") is True

def test_valid_url():
    assert is_valid_target("https://example.com/path") is True

def test_valid_url_with_query_params():
    """URLs with & in query strings must pass (not rejected as shell metachars)."""
    assert is_valid_target("https://example.com/page?a=1&b=2") is True

def test_empty_string():
    assert is_valid_target("") is False

def test_shell_metachar_semicolon():
    assert is_valid_target("example.com; rm -rf /") is False

def test_shell_metachar_pipe():
    assert is_valid_target("example.com | cat /etc/passwd") is False

def test_shell_metachar_backtick():
    assert is_valid_target("`whoami`.example.com") is False

def test_shell_metachar_dollar():
    assert is_valid_target("$(whoami).example.com") is False

def test_newline_injection():
    assert is_valid_target("example.com\nid") is False


# --- is_valid_domain (domain / subdomain only, no IP/CIDR) ---

def test_domain_valid():
    assert is_valid_domain("example.com") is True

def test_domain_subdomain():
    assert is_valid_domain("sub.example.com") is True

def test_domain_rejects_ip():
    assert is_valid_domain("192.168.1.1") is False

def test_domain_rejects_shell():
    assert is_valid_domain("example.com; id") is False

def test_domain_rejects_empty():
    assert is_valid_domain("") is False


# --- sanitize_additional_args ---

def test_sanitize_args_safe():
    assert sanitize_additional_args("-p 80 --open") == "-p 80 --open"

def test_sanitize_args_rejects_semicolon():
    assert sanitize_additional_args("-p 80; rm -rf /") is None

def test_sanitize_args_rejects_pipe():
    assert sanitize_additional_args("-p 80 | cat /etc/passwd") is None

def test_sanitize_args_rejects_backtick():
    assert sanitize_additional_args("`whoami`") is None

def test_sanitize_args_empty():
    assert sanitize_additional_args("") == ""
