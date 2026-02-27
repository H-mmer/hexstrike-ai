# hexstrike_mcp_tools/registry.py
"""SmartToolRegistry — maps grouped tool categories to Flask route endpoints."""
from typing import Dict, Any, List, Optional


class SmartToolRegistry:
    """Maps (category, tool_name) to (route, method, description).

    Used by grouped MCP endpoints to dispatch calls to the correct
    Flask route via the HexStrike API client.
    """

    def __init__(self):
        self._categories: Dict[str, Dict[str, Dict[str, str]]] = {}

    def register(self, category: str, tool_name: str, route: str,
                 method: str = "POST", description: str = "") -> None:
        if category not in self._categories:
            self._categories[category] = {}
        self._categories[category][tool_name] = {
            "route": route,
            "method": method,
            "description": description,
        }

    def get_route(self, category: str, tool_name: str) -> Dict[str, str]:
        if category not in self._categories:
            raise KeyError(f"Unknown category: {category}")
        if tool_name not in self._categories[category]:
            raise KeyError(f"Unknown tool '{tool_name}' in category '{category}'. "
                           f"Available: {list(self._categories[category].keys())}")
        return self._categories[category][tool_name]

    def list_tools(self, category: str = None) -> Dict[str, Any]:
        if category is not None:
            if category not in self._categories:
                raise KeyError(f"Unknown category: {category}")
            return {name: info["description"]
                    for name, info in self._categories[category].items()}
        return {cat: {name: info["description"] for name, info in tools.items()}
                for cat, tools in self._categories.items()}

    def list_categories(self) -> List[str]:
        return sorted(self._categories.keys())

    def tool_count(self) -> int:
        return sum(len(tools) for tools in self._categories.values())
