"""QuickMode - Install Essential Tier Tools Only

Installs approximately 20 core security tools for rapid deployment.
Ideal for: CTF competitions, quick pentests, minimal installations.
"""

import yaml
from pathlib import Path
from typing import List


def get_quick_tools() -> List[str]:
    """Get list of essential tier tools for quick installation

    Returns:
        List of tool names from essential tier (~20 tools)
    """
    registry_path = Path('scripts/installer/registry.yaml')

    with open(registry_path) as f:
        data = yaml.safe_load(f)

    tools = data.get('tools', {})
    essential_tools = [
        name for name, info in tools.items()
        if info.get('tier') == 'essential'
    ]

    return sorted(essential_tools)
