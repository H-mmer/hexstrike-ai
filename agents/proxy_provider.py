"""ProxyProvider: stub interface for future smart proxy rotation."""
from __future__ import annotations
from typing import Optional


class ProxyProvider:
    def get_proxy(self) -> Optional[dict]:
        return None

    def rotate(self) -> None:
        pass
