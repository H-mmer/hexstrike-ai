"""
Integration tests for category filtering.
These tests verify category logic directly (in-process) to avoid
memory-intensive subprocess spawning.
"""
import pytest
from scripts.installer.categories.network import get_network_tools
from scripts.installer.categories.web import get_web_tools
from scripts.installer.categories.cloud import get_cloud_tools
from scripts.installer.categories.binary import get_binary_tools
from scripts.installer.categories.mobile import get_mobile_tools
from scripts.installer.categories.forensics import get_forensics_tools
from scripts.installer.modes.quick import get_quick_tools
from scripts.installer.modes.complete import get_complete_tools
from scripts.installer.main import validate_categories, CATEGORY_FUNCTIONS


class TestCategoryFilteringIntegration:
    """Integration tests for category filtering"""

    def test_all_categories_return_tools(self):
        """Test that every category returns a non-empty list"""
        categories = {
            'network': get_network_tools,
            'web': get_web_tools,
            'cloud': get_cloud_tools,
            'binary': get_binary_tools,
            'mobile': get_mobile_tools,
            'forensics': get_forensics_tools,
        }
        for name, fn in categories.items():
            tools = fn()
            assert isinstance(tools, list), f"{name} should return a list"
            assert len(tools) >= 1, f"{name} category should have at least 1 tool"

    def test_category_tools_are_sorted(self):
        """Test that all categories return sorted tool lists"""
        for name, fn in CATEGORY_FUNCTIONS.items():
            tools = fn()
            assert tools == sorted(tools), f"{name} tools should be sorted"

    def test_no_duplicate_tools_within_category(self):
        """Test that no category contains duplicate tool names"""
        for name, fn in CATEGORY_FUNCTIONS.items():
            tools = fn()
            assert len(tools) == len(set(tools)), \
                f"{name} category contains duplicate tool names"

    def test_validate_categories_accepts_valid(self):
        """Test that valid category names pass validation"""
        valid = 'network,web,cloud,binary,mobile,forensics'
        # Should not raise
        validate_categories(valid)

    def test_validate_categories_rejects_invalid(self):
        """Test that invalid category names raise ValueError"""
        from scripts.installer.main import validate_categories
        with pytest.raises(ValueError, match="Invalid category"):
            validate_categories("network,badcategory")

    def test_validate_single_category(self):
        """Test that a single valid category passes validation"""
        for cat in ['network', 'web', 'cloud', 'binary', 'mobile', 'forensics']:
            validate_categories(cat)  # Should not raise

    def test_category_intersection_with_quick_mode(self):
        """Test that intersecting network category with quick mode works"""
        quick = set(get_quick_tools())
        network = set(get_network_tools())
        intersection = quick & network
        # There should be at least some network tools in quick mode
        assert len(intersection) >= 1, \
            "Expected at least 1 network tool in quick mode"

    def test_category_intersection_with_complete_mode(self):
        """Test that categories are subsets of complete mode"""
        complete = set(get_complete_tools())
        for name, fn in CATEGORY_FUNCTIONS.items():
            category_tools = set(fn())
            # All category tools should be in complete mode
            missing = category_tools - complete
            assert not missing, (
                f"{name} category has {len(missing)} tools not in complete mode: "
                f"{sorted(missing)[:3]}"
            )

    def test_combined_categories_union(self):
        """Test that combining categories gives the union of tools"""
        network = set(get_network_tools())
        web = set(get_web_tools())
        combined = network | web

        # Verify using CATEGORY_FUNCTIONS dict
        built = set()
        for cat in ['network', 'web']:
            built.update(CATEGORY_FUNCTIONS[cat]())

        assert built == combined

    def test_category_functions_dict_completeness(self):
        """Test that CATEGORY_FUNCTIONS covers all expected categories"""
        expected = {'network', 'web', 'cloud', 'binary', 'mobile', 'forensics'}
        actual = set(CATEGORY_FUNCTIONS.keys())
        assert expected == actual, \
            f"CATEGORY_FUNCTIONS missing: {expected - actual}"
