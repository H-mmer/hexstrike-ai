"""CompleteMode - Install All Tools

Installs all 271 tools across all tiers (essential + core + specialized).
Ideal for: Comprehensive labs, full-featured pentesting workstations.
"""

import yaml
from pathlib import Path
from typing import List


def get_complete_tools() -> List[str]:
    """Get list of all tools for complete installation

    Returns:
        List of all tool names from registry (all tiers, ~271 tools)
    """
    registry_path = Path('scripts/installer/registry.yaml')

    with open(registry_path) as f:
        data = yaml.safe_load(f)

    tools = data.get('tools', {})

    return sorted(tools.keys())
