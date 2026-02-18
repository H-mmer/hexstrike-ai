"""Binary Analysis & Reverse Engineering Category

Tools for binary analysis, reverse engineering, debugging,
disassembly, and exploit development.
"""

import yaml
from pathlib import Path
from typing import List


def get_binary_tools() -> List[str]:
    """Get all binary analysis and reverse engineering tools

    Returns:
        List[str]: Sorted list of binary analysis tool names
    """
    registry_path = Path('scripts/installer/registry.yaml')

    with open(registry_path) as f:
        data = yaml.safe_load(f)

    tools = data.get('tools', {})
    binary_tools = [
        name for name, info in tools.items()
        if info.get('category') in ('binary', 'binary-enhanced')
    ]

    return sorted(binary_tools)
