"""
Integration tests for installation modes.
These tests verify mode logic directly (in-process) to avoid
memory-intensive subprocess spawning.
"""
import pytest
from scripts.installer.modes.quick import get_quick_tools
from scripts.installer.modes.standard import get_standard_tools
from scripts.installer.modes.complete import get_complete_tools


class TestModesIntegration:
    """Integration tests for installation modes"""

    def test_quick_mode_returns_tools(self):
        """Test that quick mode returns a non-empty tool list"""
        tools = get_quick_tools()
        assert isinstance(tools, list)
        assert len(tools) >= 20, f"Expected >= 20 quick tools, got {len(tools)}"

    def test_standard_mode_returns_tools(self):
        """Test that standard mode returns a non-empty tool list"""
        tools = get_standard_tools()
        assert isinstance(tools, list)
        assert len(tools) >= 20, f"Expected >= 20 standard tools, got {len(tools)}"

    def test_complete_mode_returns_tools(self):
        """Test that complete mode returns a non-empty tool list"""
        tools = get_complete_tools()
        assert isinstance(tools, list)
        assert len(tools) >= 100, f"Expected >= 100 complete tools, got {len(tools)}"

    def test_standard_includes_quick_tools(self):
        """Test that standard mode is a superset of quick mode"""
        quick_tools = set(get_quick_tools())
        standard_tools = set(get_standard_tools())
        missing = quick_tools - standard_tools
        assert not missing, (
            f"Standard mode missing {len(missing)} quick tools: {sorted(missing)[:5]}"
        )

    def test_complete_includes_standard_tools(self):
        """Test that complete mode is a superset of standard mode"""
        standard_tools = set(get_standard_tools())
        complete_tools = set(get_complete_tools())
        missing = standard_tools - complete_tools
        assert not missing, (
            f"Complete mode missing {len(missing)} standard tools: {sorted(missing)[:5]}"
        )

    def test_complete_includes_quick_tools(self):
        """Test that complete mode is a superset of quick mode"""
        quick_tools = set(get_quick_tools())
        complete_tools = set(get_complete_tools())
        missing = quick_tools - complete_tools
        assert not missing, (
            f"Complete mode missing {len(missing)} quick tools: {sorted(missing)[:5]}"
        )

    def test_mode_hierarchy(self):
        """Test that quick ⊆ standard ⊆ complete"""
        quick = set(get_quick_tools())
        standard = set(get_standard_tools())
        complete = set(get_complete_tools())
        assert quick <= standard <= complete, "Mode hierarchy violated: quick ⊆ standard ⊆ complete"

    def test_tools_are_sorted(self):
        """Test that all modes return sorted tool lists"""
        quick = get_quick_tools()
        standard = get_standard_tools()
        complete = get_complete_tools()
        assert quick == sorted(quick), "Quick tools should be sorted"
        assert standard == sorted(standard), "Standard tools should be sorted"
        assert complete == sorted(complete), "Complete tools should be sorted"

    def test_no_duplicate_tools(self):
        """Test that no mode contains duplicate tool names"""
        for name, tools in [
            ("quick", get_quick_tools()),
            ("standard", get_standard_tools()),
            ("complete", get_complete_tools()),
        ]:
            assert len(tools) == len(set(tools)), \
                f"{name} mode contains duplicate tool names"
