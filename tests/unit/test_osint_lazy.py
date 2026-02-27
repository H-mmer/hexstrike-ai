"""Verify osint Blueprint has no top-level tool imports."""
import ast
import os


def test_no_top_level_tool_imports():
    path = os.path.join("core", "routes", "osint.py")
    with open(path) as f:
        tree = ast.parse(f.read())
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if hasattr(node, "module") and node.module and node.module.startswith("tools."):
                raise AssertionError(
                    f"Top-level tool import found in osint.py: 'from {node.module} import ...'"
                )
