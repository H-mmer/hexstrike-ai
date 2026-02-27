# tests/unit/test_installer/test_registry_expansion.py
"""Tests for registry expansion — Phase 6."""
import yaml
from pathlib import Path


def _load_registry():
    with open(Path("scripts/installer/registry.yaml")) as f:
        return yaml.safe_load(f)


def test_registry_has_at_least_145_tools():
    data = _load_registry()
    tools = data.get("tools", {})
    assert len(tools) >= 145, f"Expected >=145, got {len(tools)}"


def test_no_duplicate_tool_names():
    """Registry must not have duplicate entries."""
    import re
    with open(Path("scripts/installer/registry.yaml")) as f:
        content = f.read()
    names = re.findall(r"^  (\w[\w-]*):", content, re.MULTILINE)
    dupes = [n for n in names if names.count(n) > 1]
    assert dupes == [], f"Duplicate tool names: {set(dupes)}"


def test_mobile_tools_in_registry():
    data = _load_registry()
    tools = data.get("tools", {})
    for name in ["apktool", "jadx", "androguard", "frida", "dex2jar", "objection", "drozer"]:
        assert name in tools, f"Missing mobile tool: {name}"


def test_wireless_tools_in_registry():
    data = _load_registry()
    tools = data.get("tools", {})
    for name in ["wifite2", "airgeddon", "bettercap", "reaver"]:
        assert name in tools, f"Missing wireless tool: {name}"


def test_new_tools_have_required_fields():
    data = _load_registry()
    tools = data.get("tools", {})
    for name, info in tools.items():
        assert "package" in info, f"{name} missing 'package'"
        assert "manager" in info, f"{name} missing 'manager'"
        assert "category" in info, f"{name} missing 'category'"
        assert "tier" in info, f"{name} missing 'tier'"
        assert "description" in info, f"{name} missing 'description'"


def test_all_categories_represented():
    data = _load_registry()
    tools = data.get("tools", {})
    categories = {info["category"] for info in tools.values()}
    for cat in ["network", "web", "cloud", "binary", "mobile", "forensics"]:
        assert cat in categories, f"Missing category: {cat}"
