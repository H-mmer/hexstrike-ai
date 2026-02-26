# tests/unit/test_cache_manager_v2.py
"""Integration tests: cache_manager module must expose DiskTieredCache singleton."""


def test_module_level_cache_is_disk_tiered():
    from managers import cache_manager
    from managers.disk_cache import DiskTieredCache
    assert isinstance(cache_manager.cache, DiskTieredCache)


def test_cache_set_get_roundtrip():
    from managers.cache_manager import cache
    cache.set("roundtrip_key", {"ok": True}, ttl=30)
    assert cache.get("roundtrip_key") == {"ok": True}


def test_cache_stats_has_tier_info():
    from managers.cache_manager import cache
    stats = cache.get_stats()
    assert "mem_size_mb" in stats
    assert "disk_size_mb" in stats
