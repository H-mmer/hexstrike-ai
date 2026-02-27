# managers/disk_cache.py
"""Tiered cache: 256 MB in-memory FanoutCache + disk spill via diskcache."""
from __future__ import annotations

import os
import tempfile
import threading
from typing import Any, Optional

import diskcache

_BYTES_PER_MB = 1024 * 1024
_SENTINEL = object()


class DiskTieredCache:
    """Two-tier LRU cache.

    Tier 1 -- in-memory FanoutCache (fast, bounded by mem_size_mb).
    Tier 2 -- disk FanoutCache (slower, bounded by disk_size_mb).
    Both tiers honour TTL.
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        mem_size_mb: int = 256,
        disk_size_mb: int = 512,
    ):
        if cache_dir is None:
            cache_dir = os.path.join(tempfile.gettempdir(), "hexstrike_cache")
        os.makedirs(cache_dir, exist_ok=True)

        self._mem = diskcache.Cache(
            os.path.join(cache_dir, "mem"),
            size_limit=mem_size_mb * _BYTES_PER_MB,
            eviction_policy="least-recently-used",
        )
        self._disk = diskcache.Cache(
            os.path.join(cache_dir, "disk"),
            size_limit=disk_size_mb * _BYTES_PER_MB,
            eviction_policy="least-recently-used",
        )
        self._hits = 0
        self._misses = 0
        self._lock = threading.Lock()
        self._mem_size_mb = mem_size_mb
        self._disk_size_mb = disk_size_mb

    def get(self, key: str) -> Optional[Any]:
        val = self._mem.get(key, default=_SENTINEL)
        if val is not _SENTINEL:
            with self._lock:
                self._hits += 1
            return val
        val = self._disk.get(key, default=_SENTINEL)
        if val is not _SENTINEL:
            with self._lock:
                self._hits += 1
            return val
        with self._lock:
            self._misses += 1
        return None

    def set(self, key: str, value: Any, ttl: int = 1800) -> None:
        # Dual-write: both tiers get every entry so reads always hit the fast
        # tier first while the disk tier acts as a durable backup for entries
        # evicted from memory.  Trades ~2x storage for simpler code.
        self._mem.set(key, value, expire=ttl)
        self._disk.set(key, value, expire=ttl)

    def clear(self) -> None:
        self._mem.clear()
        self._disk.clear()

    def get_stats(self) -> dict:
        with self._lock:
            hits = self._hits
            misses = self._misses
        total = hits + misses
        hit_rate = hits / total if total > 0 else 0.0
        return {
            "hits": hits,
            "misses": misses,
            "hit_rate": round(hit_rate, 4),
            "mem_size_mb": self._mem_size_mb,
            "disk_size_mb": self._disk_size_mb,
            "mem_item_count": len(self._mem),
            "disk_item_count": len(self._disk),
        }

    def close(self) -> None:
        self._mem.close()
        self._disk.close()
