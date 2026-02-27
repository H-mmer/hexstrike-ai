"""Unit tests for CTF, BugBounty, and Intelligence workflow Blueprint routes."""
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask


def test_ctf_blueprint_registers():
    from core.routes.ctf import ctf_bp
    app = Flask(__name__)
    app.register_blueprint(ctf_bp)
    assert 'ctf' in app.blueprints


def test_bugbounty_blueprint_registers():
    from core.routes.bugbounty import bugbounty_bp
    app = Flask(__name__)
    app.register_blueprint(bugbounty_bp)
    assert 'bugbounty' in app.blueprints


def test_intelligence_blueprint_registers():
    from core.routes.intelligence import intelligence_bp
    app = Flask(__name__)
    app.register_blueprint(intelligence_bp)
    assert 'intelligence' in app.blueprints


def test_ctf_route_exists():
    from core.routes.ctf import ctf_bp
    app = Flask(__name__)
    app.register_blueprint(ctf_bp)
    app.config['TESTING'] = True
    rules = [str(r) for r in app.url_map.iter_rules()]
    ctf_routes = [r for r in rules if 'ctf' in r.lower()]
    assert len(ctf_routes) >= 1


def test_intelligence_route_exists():
    from core.routes.intelligence import intelligence_bp
    app = Flask(__name__)
    app.register_blueprint(intelligence_bp)
    app.config['TESTING'] = True
    rules = [str(r) for r in app.url_map.iter_rules()]
    intel_routes = [r for r in rules if 'intelligence' in r.lower() or 'vuln' in r.lower() or 'ai' in r.lower()]
    assert len(intel_routes) >= 1


# ---------------------------------------------------------------------------
# CTF route handler tests
# ---------------------------------------------------------------------------

@pytest.fixture
def ctf_app():
    from core.routes.ctf import ctf_bp
    app = Flask(__name__)
    app.register_blueprint(ctf_bp)
    app.config['TESTING'] = True
    return app


def test_ctf_create_workflow_missing_name(ctf_app):
    resp = ctf_app.test_client().post('/api/ctf/create-challenge-workflow', json={})
    assert resp.status_code == 400


def test_ctf_create_workflow_success(ctf_app):
    resp = ctf_app.test_client().post('/api/ctf/create-challenge-workflow',
                                      json={'name': 'test-challenge', 'category': 'web'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_ctf_auto_solve_missing_name(ctf_app):
    resp = ctf_app.test_client().post('/api/ctf/auto-solve-challenge', json={})
    assert resp.status_code == 400


def test_ctf_auto_solve_success(ctf_app):
    resp = ctf_app.test_client().post('/api/ctf/auto-solve-challenge',
                                      json={'name': 'test-challenge', 'category': 'crypto'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_ctf_suggest_tools_missing_description(ctf_app):
    resp = ctf_app.test_client().post('/api/ctf/suggest-tools', json={})
    assert resp.status_code == 400


def test_ctf_suggest_tools_success(ctf_app):
    resp = ctf_app.test_client().post('/api/ctf/suggest-tools',
                                      json={'description': 'base64 encoded string', 'category': 'crypto'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_ctf_team_strategy_missing_challenges(ctf_app):
    resp = ctf_app.test_client().post('/api/ctf/team-strategy', json={})
    assert resp.status_code == 400


def test_ctf_team_strategy_success(ctf_app):
    challenges = [{'name': 'chall1', 'category': 'web', 'difficulty': 'easy', 'points': 100}]
    resp = ctf_app.test_client().post('/api/ctf/team-strategy',
                                      json={'challenges': challenges})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_ctf_crypto_solver_missing_cipher(ctf_app):
    resp = ctf_app.test_client().post('/api/ctf/cryptography-solver', json={})
    assert resp.status_code == 400


def test_ctf_crypto_solver_success(ctf_app):
    resp = ctf_app.test_client().post('/api/ctf/cryptography-solver',
                                      json={'cipher_text': 'aGVsbG8=', 'cipher_type': 'unknown'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_ctf_forensics_missing_path(ctf_app):
    resp = ctf_app.test_client().post('/api/ctf/forensics-analyzer', json={})
    assert resp.status_code == 400


def test_ctf_forensics_success(ctf_app):
    with patch('core.routes.ctf.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='test output', stderr='', returncode=0)
        resp = ctf_app.test_client().post('/api/ctf/forensics-analyzer',
                                          json={'file_path': '/tmp/test.bin'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_ctf_binary_analyzer_missing_path(ctf_app):
    resp = ctf_app.test_client().post('/api/ctf/binary-analyzer', json={})
    assert resp.status_code == 400


def test_ctf_binary_analyzer_success(ctf_app):
    with patch('core.routes.ctf.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='ELF 64-bit', stderr='', returncode=0)
        resp = ctf_app.test_client().post('/api/ctf/binary-analyzer',
                                          json={'binary_path': '/tmp/test_binary'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


# ---------------------------------------------------------------------------
# BugBounty route handler tests
# ---------------------------------------------------------------------------

@pytest.fixture
def bugbounty_app():
    from core.routes.bugbounty import bugbounty_bp
    app = Flask(__name__)
    app.register_blueprint(bugbounty_bp)
    app.config['TESTING'] = True
    return app


def test_bugbounty_recon_missing_domain(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/reconnaissance-workflow', json={})
    assert resp.status_code == 400


def test_bugbounty_recon_success(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/reconnaissance-workflow',
                                            json={'domain': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_bugbounty_vuln_hunt_missing_domain(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/vulnerability-hunting-workflow', json={})
    assert resp.status_code == 400


def test_bugbounty_vuln_hunt_success(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/vulnerability-hunting-workflow',
                                            json={'domain': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_bugbounty_business_logic_missing_domain(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/business-logic-workflow', json={})
    assert resp.status_code == 400


def test_bugbounty_business_logic_success(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/business-logic-workflow',
                                            json={'domain': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_bugbounty_osint_missing_domain(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/osint-workflow', json={})
    assert resp.status_code == 400


def test_bugbounty_osint_success(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/osint-workflow',
                                            json={'domain': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_bugbounty_file_upload_missing_url(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/file-upload-testing', json={})
    assert resp.status_code == 400


def test_bugbounty_file_upload_success(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/file-upload-testing',
                                            json={'target_url': 'http://example.com/upload'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_bugbounty_comprehensive_missing_domain(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/comprehensive-assessment', json={})
    assert resp.status_code == 400


def test_bugbounty_comprehensive_success(bugbounty_app):
    resp = bugbounty_app.test_client().post('/api/bugbounty/comprehensive-assessment',
                                            json={'domain': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


# ---------------------------------------------------------------------------
# Intelligence route handler tests
# ---------------------------------------------------------------------------

@pytest.fixture
def intel_app():
    from core.routes.intelligence import intelligence_bp
    app = Flask(__name__)
    app.register_blueprint(intelligence_bp)
    app.config['TESTING'] = True
    return app


def test_analyze_target_missing_target(intel_app):
    resp = intel_app.test_client().post('/api/intelligence/analyze-target', json={})
    assert resp.status_code == 400


def test_analyze_target_success(intel_app):
    resp = intel_app.test_client().post('/api/intelligence/analyze-target',
                                        json={'target': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_select_tools_missing_target(intel_app):
    resp = intel_app.test_client().post('/api/intelligence/select-tools', json={})
    assert resp.status_code == 400


def test_select_tools_success(intel_app):
    resp = intel_app.test_client().post('/api/intelligence/select-tools',
                                        json={'target': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_optimize_params_missing_fields(intel_app):
    resp = intel_app.test_client().post('/api/intelligence/optimize-parameters', json={})
    assert resp.status_code == 400


def test_optimize_params_success(intel_app):
    resp = intel_app.test_client().post('/api/intelligence/optimize-parameters',
                                        json={'target': 'example.com', 'tool': 'nmap'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_attack_chain_missing_target(intel_app):
    resp = intel_app.test_client().post('/api/intelligence/create-attack-chain', json={})
    assert resp.status_code == 400


def test_attack_chain_success(intel_app):
    resp = intel_app.test_client().post('/api/intelligence/create-attack-chain',
                                        json={'target': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_technology_detection_missing_target(intel_app):
    resp = intel_app.test_client().post('/api/intelligence/technology-detection', json={})
    assert resp.status_code == 400


def test_technology_detection_success(intel_app):
    resp = intel_app.test_client().post('/api/intelligence/technology-detection',
                                        json={'target': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_cve_monitor_success(intel_app):
    resp = intel_app.test_client().post('/api/vuln-intel/cve-monitor', json={'hours': 24})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_exploit_generate_missing_cve(intel_app):
    resp = intel_app.test_client().post('/api/vuln-intel/exploit-generate', json={})
    assert resp.status_code == 400


def test_attack_chains_missing_software(intel_app):
    resp = intel_app.test_client().post('/api/vuln-intel/attack-chains', json={})
    assert resp.status_code == 400


def test_threat_feeds_missing_indicators(intel_app):
    resp = intel_app.test_client().post('/api/vuln-intel/threat-feeds', json={})
    assert resp.status_code == 400


def test_threat_feeds_success(intel_app):
    resp = intel_app.test_client().post('/api/vuln-intel/threat-feeds',
                                        json={'indicators': ['CVE-2021-44228']})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_ai_generate_payload_success(intel_app):
    resp = intel_app.test_client().post('/api/ai/generate_payload',
                                        json={'attack_type': 'xss'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True


def test_ai_test_payload_missing_fields(intel_app):
    resp = intel_app.test_client().post('/api/ai/test_payload', json={})
    assert resp.status_code == 400


def test_advanced_payload_generation_missing_type(intel_app):
    resp = intel_app.test_client().post('/api/ai/advanced-payload-generation', json={})
    assert resp.status_code == 400


def test_advanced_payload_generation_success(intel_app):
    resp = intel_app.test_client().post('/api/ai/advanced-payload-generation',
                                        json={'attack_type': 'xss', 'evasion_level': 'standard'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True
