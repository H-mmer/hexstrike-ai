#!/usr/bin/env python3
"""
HexStrike AI - Cache Manager

Extracted from monolithic hexstrike_server.py for modular architecture.
"""

import logging
import subprocess
import psutil
import time
import shutil
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import OrderedDict
from datetime import datetime, timedelta
import threading
import queue
from core.constants import CACHE_SIZE, CACHE_TTL

logger = logging.getLogger(__name__)


class HexStrikeCache:
    """Advanced caching system for command results"""

    def __init__(self, max_size: int = CACHE_SIZE, ttl: int = CACHE_TTL):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}
        self._lock = threading.Lock()

    def _generate_key(self, command: str, params: Dict[str, Any]) -> str:
        """Generate cache key from command and parameters"""
        key_data = f"{command}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _is_expired(self, timestamp: float) -> bool:
        """Check if cache entry is expired"""
        return time.time() - timestamp > self.ttl

    def get(self, command: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired"""
        key = self._generate_key(command, params)

        with self._lock:
            if key in self.cache:
                timestamp, data = self.cache[key]
                if not self._is_expired(timestamp):
                    self.cache.move_to_end(key)
                    self.stats["hits"] += 1
                    logger.info(f"💾 Cache HIT for command: {command}")
                    return data
                else:
                    del self.cache[key]

            self.stats["misses"] += 1
            logger.info(f"🔍 Cache MISS for command: {command}")
            return None

    def set(self, command: str, params: Dict[str, Any], result: Dict[str, Any]):
        """Store result in cache"""
        key = self._generate_key(command, params)

        with self._lock:
            while len(self.cache) >= self.max_size:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                self.stats["evictions"] += 1
            self.cache[key] = (time.time(), result)
            logger.info(f"💾 Cached result for command: {command}")

    def clear(self) -> None:
        """Clear all cache entries and reset statistics."""
        with self._lock:
            self.cache.clear()
            self.stats = {"hits": 0, "misses": 0, "evictions": 0}

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self.stats["hits"] + self.stats["misses"]
            hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hit_rate": f"{hit_rate:.1f}%",
                "hits": self.stats["hits"],
                "misses": self.stats["misses"],
                "evictions": self.stats["evictions"]
            }

# Use DiskTieredCache as primary singleton (tiered: 256 MB mem + 512 MB disk)
# HexStrikeCache kept above for backwards compatibility with existing tests.
from managers.disk_cache import DiskTieredCache as _DiskTieredCache
cache = _DiskTieredCache(mem_size_mb=256, disk_size_mb=512)

