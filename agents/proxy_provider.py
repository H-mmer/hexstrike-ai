# agents/proxy_provider.py
"""ProxyProvider: round-robin proxy rotation."""
from __future__ import annotations

import os
from typing import List, Optional


class ProxyProvider:
    """Rotate through a list of proxy dicts in round-robin order."""

    def __init__(self, proxies: Optional[List[dict]] = None):
        self._proxies = proxies or []
        self._index = 0

    def get_proxy(self) -> Optional[dict]:
        if not self._proxies:
            return None
        return self._proxies[self._index % len(self._proxies)]

    def rotate(self) -> None:
        if self._proxies:
            self._index = (self._index + 1) % len(self._proxies)

    @classmethod
    def from_env(cls) -> "ProxyProvider":
        raw = os.environ.get("HEXSTRIKE_PROXIES", "")
        if not raw.strip():
            return cls()
        urls = [u.strip() for u in raw.split(",") if u.strip()]
        proxies = [{"http": u, "https": u} for u in urls]
        return cls(proxies=proxies)
