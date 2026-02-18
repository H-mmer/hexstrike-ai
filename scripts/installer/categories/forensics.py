"""Forensics & Malware Analysis Category

Tools for digital forensics, memory analysis, malware analysis,
incident response, and threat hunting.
"""

import yaml
from pathlib import Path
from typing import List


def get_forensics_tools() -> List[str]:
    """Get all forensics and malware analysis tools

    Returns:
        List[str]: Sorted list of forensics tool names
    """
    registry_path = Path('scripts/installer/registry.yaml')

    with open(registry_path) as f:
        data = yaml.safe_load(f)

    tools = data.get('tools', {})
    forensics_tools = [
        name for name, info in tools.items()
        if info.get('category') in ('forensics', 'malware')
    ]

    return sorted(forensics_tools)
