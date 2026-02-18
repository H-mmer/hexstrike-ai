"""Web Application Security Category

Tools for web scanning, directory bruteforcing, vulnerability scanning,
SQL injection, XSS, and web application testing.
"""

import yaml
from pathlib import Path
from typing import List


def get_web_tools() -> List[str]:
    """Get all web application security tools

    Returns:
        List[str]: Sorted list of web security tool names
    """
    registry_path = Path('scripts/installer/registry.yaml')

    with open(registry_path) as f:
        data = yaml.safe_load(f)

    tools = data.get('tools', {})
    web_tools = [
        name for name, info in tools.items()
        if info.get('category') in ('web', 'web-enhanced')
    ]

    return sorted(web_tools)
