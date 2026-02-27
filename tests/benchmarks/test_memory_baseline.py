"""
Memory baseline: measure RSS before/after Blueprint registration.
Run manually: python tests/benchmarks/test_memory_baseline.py

NOT collected by pytest — this is a manual benchmark script.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import tracemalloc
import psutil


def measure_rss_mb() -> float:
    proc = psutil.Process(os.getpid())
    return proc.memory_info().rss / (1024 * 1024)


def main():
    rss_before = measure_rss_mb()
    tracemalloc.start()

    # Import Flask app (triggers Blueprint registration)
    from core.server import create_app
    app = create_app()

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_after = measure_rss_mb()

    print(f"RSS before: {rss_before:.1f} MB")
    print(f"RSS after:  {rss_after:.1f} MB")
    print(f"Delta:      {rss_after - rss_before:.1f} MB")
    print(f"tracemalloc peak: {peak / (1024*1024):.1f} MB")


if __name__ == "__main__":
    main()
