"""StandardMode - Install Essential + Core Tier Tools

Installs approximately 36 tools (essential + core tiers).
Ideal for: Bug bounty hunting, standard pentests, balanced installations.
"""

import yaml
from pathlib import Path
from typing import List


def get_standard_tools() -> List[str]:
    """Get list of essential + core tier tools for standard installation

    Returns:
        List of tool names from essential and core tiers (~36 tools)
    """
    registry_path = Path('scripts/installer/registry.yaml')

    with open(registry_path) as f:
        data = yaml.safe_load(f)

    tools = data.get('tools', {})
    standard_tools = [
        name for name, info in tools.items()
        if info.get('tier') in ('essential', 'core')
    ]

    return sorted(standard_tools)
