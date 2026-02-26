"""
Lazy import helper for optional security tool modules.

Usage:
    shodan_search, _ok = lazy_load("tools.osint.passive_recon", "shodan_search")
    # _ok is True if import succeeded; False provides a safe stub.
"""
from __future__ import annotations
from typing import Callable, Tuple, Any


def lazy_load(module_path: str, func_name: str) -> Tuple[Callable, bool]:
    """Import module_path.func_name on first call.

    Returns (callable, True) on success.
    Returns (stub_returning_error_dict, False) on ImportError.
    """
    try:
        import importlib
        mod = importlib.import_module(module_path)
        fn = getattr(mod, func_name)
        return fn, True
    except (ImportError, AttributeError):
        module_label = f"{module_path}.{func_name}"

        def _stub(*args: Any, **kwargs: Any) -> dict:
            return {"success": False, "error": f"{module_label} not available"}

        return _stub, False
