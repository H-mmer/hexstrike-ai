#!/usr/bin/env python3
"""Tests for ResourceMonitor singleton — written BEFORE implementation (TDD)."""
import pytest
from unittest.mock import patch


def test_get_memory_percent_returns_float(monkeypatch):
    """memory_percent() should delegate to psutil and return the value."""
    import psutil
    with patch.object(psutil, "virtual_memory") as mock_vm:
        mock_vm.return_value.percent = 45.3
        from managers.resource_monitor import ResourceMonitor
        rm = ResourceMonitor()
        assert rm.memory_percent() == 45.3


def test_memory_pressure_true_when_above_threshold():
    """is_memory_pressure() returns True when usage >= threshold."""
    from managers.resource_monitor import ResourceMonitor
    rm = ResourceMonitor(memory_threshold=80.0)
    with patch.object(rm, "memory_percent", return_value=85.0):
        assert rm.is_memory_pressure() is True


def test_memory_pressure_false_when_below_threshold():
    """is_memory_pressure() returns False when usage < threshold."""
    from managers.resource_monitor import ResourceMonitor
    rm = ResourceMonitor(memory_threshold=80.0)
    with patch.object(rm, "memory_percent", return_value=50.0):
        assert rm.is_memory_pressure() is False


def test_cpu_pressure_true_when_above_threshold():
    """is_cpu_pressure() returns True when usage >= threshold."""
    from managers.resource_monitor import ResourceMonitor
    rm = ResourceMonitor(cpu_threshold=90.0)
    with patch.object(rm, "cpu_percent", return_value=95.0):
        assert rm.is_cpu_pressure() is True


def test_cpu_pressure_false_when_below_threshold():
    """is_cpu_pressure() returns False when usage < threshold."""
    from managers.resource_monitor import ResourceMonitor
    rm = ResourceMonitor(cpu_threshold=90.0)
    with patch.object(rm, "cpu_percent", return_value=40.0):
        assert rm.is_cpu_pressure() is False


def test_singleton_returns_same_instance():
    """get_resource_monitor() must return the same object on repeated calls."""
    import managers.resource_monitor as mod
    # Reset singleton state to avoid pollution from earlier tests
    mod._instance = None
    try:
        a = mod.get_resource_monitor()
        b = mod.get_resource_monitor()
        assert a is b
    finally:
        # Clean up to avoid polluting other tests
        mod._instance = None


def test_default_thresholds():
    """Default thresholds should be 85% memory and 90% CPU."""
    from managers.resource_monitor import ResourceMonitor
    rm = ResourceMonitor()
    assert rm.memory_threshold == 85.0
    assert rm.cpu_threshold == 90.0


def test_custom_thresholds():
    """Constructor should accept custom threshold values."""
    from managers.resource_monitor import ResourceMonitor
    rm = ResourceMonitor(memory_threshold=70.0, cpu_threshold=80.0)
    assert rm.memory_threshold == 70.0
    assert rm.cpu_threshold == 80.0
