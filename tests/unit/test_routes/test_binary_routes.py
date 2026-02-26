"""Unit tests for the binary analysis and forensics tool routes Blueprint."""
import sys
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.binary import binary_bp


@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(binary_bp)
    a.config['TESTING'] = True
    return a


# ---------------------------------------------------------------------------
# gdb
# ---------------------------------------------------------------------------

def test_gdb_route_missing_binary(app):
    resp = app.test_client().post('/api/tools/gdb', json={})
    assert resp.status_code == 400


def test_gdb_route_exists(app):
    with patch('core.routes.binary.subprocess.run') as mock_run, \
         patch('core.routes.binary.shutil.which', return_value='/usr/bin/gdb'):
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/gdb',
                                      json={'binary': '/tmp/test_binary'})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()


def test_gdb_route_tool_missing(app):
    with patch('core.routes.binary.shutil.which', return_value=None):
        resp = app.test_client().post('/api/tools/gdb',
                                      json={'binary': '/tmp/test_binary'})
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# binwalk
# ---------------------------------------------------------------------------

def test_binwalk_route_missing_file(app):
    resp = app.test_client().post('/api/tools/binwalk', json={})
    assert resp.status_code == 400


def test_binwalk_route_exists(app):
    with patch('core.routes.binary.subprocess.run') as mock_run, \
         patch('core.routes.binary.shutil.which', return_value='/usr/bin/binwalk'):
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/binwalk',
                                      json={'file_path': '/tmp/firmware.bin'})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()


def test_binwalk_route_tool_missing(app):
    with patch('core.routes.binary.shutil.which', return_value=None):
        resp = app.test_client().post('/api/tools/binwalk',
                                      json={'file_path': '/tmp/firmware.bin'})
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Phase 3: yara (fallback subprocess path)
# ---------------------------------------------------------------------------

def test_binary_yara_route_missing_file(app):
    resp = app.test_client().post('/api/tools/binary/yara', json={})
    assert resp.status_code == 400


def test_binary_yara_route_exists(app):
    with patch.dict(sys.modules, {'tools.binary.malware_analysis': None}), \
         patch('core.routes.binary.subprocess.run') as mock_run, \
         patch('core.routes.binary.shutil.which', return_value='/usr/bin/yara'):
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/binary/yara',
                                      json={'file': '/tmp/sample.exe',
                                            'rules': '/tmp/rules.yar'})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()


def test_binary_yara_route_tool_missing(app):
    with patch.dict(sys.modules, {'tools.binary.malware_analysis': None}), \
         patch('core.routes.binary.shutil.which', return_value=None):
        resp = app.test_client().post('/api/tools/binary/yara',
                                      json={'file': '/tmp/sample.exe'})
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Phase 3: floss (fallback subprocess path)
# ---------------------------------------------------------------------------

def test_binary_floss_route_missing_file(app):
    resp = app.test_client().post('/api/tools/binary/floss', json={})
    assert resp.status_code == 400


def test_binary_floss_route_exists(app):
    with patch.dict(sys.modules, {'tools.binary.malware_analysis': None}), \
         patch('core.routes.binary.subprocess.run') as mock_run, \
         patch('core.routes.binary.shutil.which', return_value='/usr/bin/floss'):
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/binary/floss',
                                      json={'file': '/tmp/malware.exe'})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()


# ---------------------------------------------------------------------------
# Phase 3: rizin (fallback subprocess path)
# ---------------------------------------------------------------------------

def test_binary_rizin_route_missing_binary(app):
    resp = app.test_client().post('/api/tools/binary/rizin', json={})
    assert resp.status_code == 400


def test_binary_rizin_route_exists(app):
    with patch.dict(sys.modules, {'tools.binary.enhanced_binary': None}), \
         patch('core.routes.binary.subprocess.run') as mock_run, \
         patch('core.routes.binary.shutil.which', return_value='/usr/bin/rizin'):
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/binary/rizin',
                                      json={'binary': '/tmp/test_binary'})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()


# ---------------------------------------------------------------------------
# Phase 3: forensics (fallback subprocess path)
# ---------------------------------------------------------------------------

def test_binary_forensics_route_missing_image(app):
    resp = app.test_client().post('/api/tools/binary/forensics', json={})
    assert resp.status_code == 400


def test_binary_forensics_route_exists(app):
    with patch.dict(sys.modules, {'tools.binary.forensics': None}), \
         patch('core.routes.binary.subprocess.run') as mock_run, \
         patch('core.routes.binary.shutil.which', return_value='/usr/bin/fls'):
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/binary/forensics',
                                      json={'image_path': '/tmp/disk.img'})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()
