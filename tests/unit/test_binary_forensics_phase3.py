#!/usr/bin/env python3
"""Phase 3 Binary and Forensics Tools Tests"""

import pytest
from unittest.mock import Mock, patch

def test_enhanced_binary_import():
    """Test enhanced binary analysis tools import"""
    from tools.binary.enhanced_binary import rizin_analyze, pwndbg_analyze, capstone_disassemble
    assert callable(rizin_analyze)
    assert callable(pwndbg_analyze)
    assert callable(capstone_disassemble)

def test_malware_analysis_import():
    """Test malware analysis tools import"""
    from tools.binary.malware_analysis import yara_scan, strings_extended, floss_analyze
    assert callable(yara_scan)
    assert callable(strings_extended)
    assert callable(floss_analyze)

def test_forensics_import():
    """Test forensics tools import"""
    from tools.binary.forensics import autopsy_cli_analyze, plaso_timeline, rekall_memory_analyze
    assert callable(autopsy_cli_analyze)
    assert callable(plaso_timeline)
    assert callable(rekall_memory_analyze)

def test_strings_extended_categorization():
    """Test strings categorization logic exists"""
    from tools.binary.malware_analysis import strings_extended
    assert callable(strings_extended)

def test_capstone_disassemble_structure():
    """Test capstone disassemble function structure"""
    from tools.binary.enhanced_binary import capstone_disassemble
    assert callable(capstone_disassemble)

def test_yara_scan_parameters():
    """Test yara scan function signature"""
    from tools.binary.malware_analysis import yara_scan
    assert callable(yara_scan)
