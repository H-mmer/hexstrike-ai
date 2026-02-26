# tests/unit/test_disk_tiered_cache.py
"""Tests for DiskTieredCache — write BEFORE implementation."""
import tempfile
import os


def test_set_and_get_returns_value():
    from managers.disk_cache import DiskTieredCache
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = DiskTieredCache(cache_dir=tmpdir, mem_size_mb=64, disk_size_mb=128)
        cache.set("key1", {"data": "value"}, ttl=60)
        result = cache.get("key1")
        assert result == {"data": "value"}
        cache.close()


def test_get_missing_key_returns_none():
    from managers.disk_cache import DiskTieredCache
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = DiskTieredCache(cache_dir=tmpdir, mem_size_mb=64, disk_size_mb=128)
        assert cache.get("nonexistent") is None
        cache.close()


def test_clear_removes_all_entries():
    from managers.disk_cache import DiskTieredCache
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = DiskTieredCache(cache_dir=tmpdir, mem_size_mb=64, disk_size_mb=128)
        cache.set("k1", "v1")
        cache.set("k2", "v2")
        cache.clear()
        assert cache.get("k1") is None
        assert cache.get("k2") is None
        cache.close()


def test_get_stats_returns_expected_keys():
    from managers.disk_cache import DiskTieredCache
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = DiskTieredCache(cache_dir=tmpdir, mem_size_mb=64, disk_size_mb=128)
        cache.set("k", "v")
        cache.get("k")  # hit
        cache.get("miss")  # miss
        stats = cache.get_stats()
        assert "hits" in stats
        assert "misses" in stats
        assert "mem_size_mb" in stats
        assert "disk_size_mb" in stats
        cache.close()


def test_ttl_expiry_returns_none():
    """Expired keys must not be returned."""
    from managers.disk_cache import DiskTieredCache
    import time
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = DiskTieredCache(cache_dir=tmpdir, mem_size_mb=64, disk_size_mb=128)
        cache.set("expiring", "val", ttl=1)
        time.sleep(1.1)
        assert cache.get("expiring") is None
        cache.close()


def test_default_cache_dir_uses_tmp():
    """Constructing without cache_dir must not raise."""
    from managers.disk_cache import DiskTieredCache
    cache = DiskTieredCache()
    cache.set("k", "v")
    assert cache.get("k") == "v"
    cache.close()
