"""Cloud Security Category

Tools for AWS, Azure, GCP security auditing, Kubernetes security,
container scanning, and cloud infrastructure testing.
"""

import yaml
from pathlib import Path
from typing import List


def get_cloud_tools() -> List[str]:
    """Get all cloud security tools

    Returns:
        List[str]: Sorted list of cloud security tool names
    """
    registry_path = Path('scripts/installer/registry.yaml')

    with open(registry_path) as f:
        data = yaml.safe_load(f)

    tools = data.get('tools', {})
    cloud_tools = [
        name for name, info in tools.items()
        if info.get('category') in ('cloud', 'cloud-enhanced')
    ]

    return sorted(cloud_tools)
