"""Network & Reconnaissance Category

Tools for network scanning, subdomain enumeration, DNS analysis,
port scanning, and reconnaissance workflows.
"""

import yaml
from pathlib import Path
from typing import List


def get_network_tools() -> List[str]:
    """Get all network and reconnaissance tools

    Returns:
        List[str]: Sorted list of network/recon tool names
    """
    registry_path = Path('scripts/installer/registry.yaml')

    with open(registry_path) as f:
        data = yaml.safe_load(f)

    tools = data.get('tools', {})
    network_tools = [
        name for name, info in tools.items()
        if info.get('category') in ('network', 'network-enhanced')
    ]

    return sorted(network_tools)
