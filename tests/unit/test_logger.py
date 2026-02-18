"""
Tests for logging module
"""

import pytest
import logging
from utils.logger import setup_basic_logging, ColoredFormatter


def test_setup_basic_logging():
    """Test basic logging setup"""
    logger = setup_basic_logging()
    assert logger is not None
    assert isinstance(logger, logging.Logger)


def test_colored_formatter():
    """Test ColoredFormatter class"""
    formatter = ColoredFormatter()
    assert formatter is not None
    assert hasattr(formatter, 'COLORS')
    assert hasattr(formatter, 'EMOJIS')
    assert 'INFO' in formatter.COLORS
    assert 'ERROR' in formatter.EMOJIS
