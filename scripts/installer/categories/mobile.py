"""Mobile Security Category

Tools for Android and iOS security testing, APK analysis,
mobile app reverse engineering, and dynamic analysis.
"""

import yaml
from pathlib import Path
from typing import List


def get_mobile_tools() -> List[str]:
    """Get all mobile security tools

    Returns:
        List[str]: Sorted list of mobile security tool names
    """
    registry_path = Path('scripts/installer/registry.yaml')

    with open(registry_path) as f:
        data = yaml.safe_load(f)

    tools = data.get('tools', {})
    mobile_tools = [
        name for name, info in tools.items()
        if info.get('category') == 'mobile'
    ]

    return sorted(mobile_tools)
