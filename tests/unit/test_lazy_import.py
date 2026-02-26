# tests/unit/test_lazy_import.py
"""Tests for core.lazy_import helper."""


def test_lazy_load_returns_importerror_result_on_failure():
    from core.lazy_import import lazy_load
    fn, available = lazy_load("nonexistent_module_xyz", "some_func")
    assert available is False
    result = fn()
    assert result["success"] is False
    assert "not available" in result["error"]


def test_lazy_load_returns_real_function_on_success():
    from core.lazy_import import lazy_load
    # os.path.join is always available
    fn, available = lazy_load("os.path", "join")
    assert available is True
    assert fn("a", "b") == "a/b"
