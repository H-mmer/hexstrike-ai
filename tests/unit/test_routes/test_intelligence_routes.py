# tests/unit/test_routes/test_intelligence_routes.py
"""Tests for intelligence Blueprint routes."""
import json
import socket
from unittest.mock import patch, MagicMock
import pytest
from core.server import create_app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_API_KEY", raising=False)
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestExploitGenerator:
    def test_exploit_lookup_with_searchsploit(self, client):
        fake_searchsploit = {
            "success": True,
            "exploits": [
                {"edb_id": "50383", "title": "Apache 2.4.49 - RCE", "path": "/exploits/50383.py"}
            ],
            "cve_id": "CVE-2021-41773",
        }
        fake_cve_analysis = {
            "success": True,
            "exploitability_level": "HIGH",
            "exploitability_score": 9.0,
        }
        fake_existing = {"exploits": []}

        with patch("core.routes.intelligence._get_cve_intelligence") as mock_cve, \
             patch("core.routes.intelligence._exploit_generator") as mock_gen:
            mock_cve_inst = MagicMock()
            mock_cve_inst.analyze_cve_exploitability.return_value = fake_cve_analysis
            mock_cve_inst.search_existing_exploits.return_value = fake_existing
            mock_cve.return_value = mock_cve_inst

            mock_gen.generate_exploit_from_cve.return_value = fake_searchsploit

            resp = client.post("/api/vuln-intel/exploit-generate", json={
                "cve_id": "CVE-2021-41773",
                "exploit_type": "poc",
            })
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True
            # Response nests under "exploit_generation"
            gen = data["exploit_generation"]
            assert len(gen["exploits"]) >= 1
            assert "50383" in gen["exploits"][0]["edb_id"]

    def test_exploit_lookup_searchsploit_missing(self, client):
        """When searchsploit is not installed, _exploit_generator returns error."""
        fake_cve_analysis = {"success": True, "exploitability_level": "MEDIUM"}

        with patch("core.routes.intelligence._get_cve_intelligence") as mock_cve, \
             patch("core.routes.intelligence._exploit_generator") as mock_gen:
            mock_cve_inst = MagicMock()
            mock_cve_inst.analyze_cve_exploitability.return_value = fake_cve_analysis
            mock_cve_inst.search_existing_exploits.return_value = {"exploits": []}
            mock_cve.return_value = mock_cve_inst

            mock_gen.generate_exploit_from_cve.return_value = {
                "success": False, "error": "searchsploit not installed"
            }

            resp = client.post("/api/vuln-intel/exploit-generate", json={
                "cve_id": "CVE-2021-41773",
            })
            data = resp.get_json()
            assert data["success"] is True  # route still succeeds
            assert data["exploit_generation"]["success"] is False
            assert "searchsploit" in data["exploit_generation"]["error"]


class TestPayloadTester:
    def test_payload_test_sends_real_request(self, client):
        with patch("core.routes.intelligence.requests_lib") as mock_req, \
             patch("core.routes.intelligence.socket") as mock_socket:
            mock_socket.getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 80))
            ]
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Content-Type": "text/html"}
            mock_resp.text = "<html><script>alert(1)</script></html>"
            mock_req.request.return_value = mock_resp
            mock_req.RequestException = Exception

            resp = client.post("/api/ai/test_payload", json={
                "payload": "<script>alert(1)</script>",
                "target_url": "http://testsite.com/search?q=",
                "method": "GET",
            })
            data = resp.get_json()
            assert data["success"] is True
            assert data["test_result"]["status_code"] == 200
            assert data["test_result"]["reflection_detected"] is True

    def test_payload_test_detects_waf(self, client):
        with patch("core.routes.intelligence.requests_lib") as mock_req, \
             patch("core.routes.intelligence.socket") as mock_socket:
            mock_socket.getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 443))
            ]
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_resp.headers = {"CF-Ray": "abc123", "Server": "cloudflare"}
            mock_resp.text = "Access denied"
            mock_req.request.return_value = mock_resp
            mock_req.RequestException = Exception

            resp = client.post("/api/ai/test_payload", json={
                "payload": "' OR 1=1--",
                "target_url": "http://testsite.com/login",
                "method": "POST",
            })
            data = resp.get_json()
            assert data["test_result"]["waf_detected"] is True

    def test_payload_test_blocks_private_ip(self, client):
        """SSRF guard: block requests to private/loopback/link-local addresses."""
        with patch("core.routes.intelligence.socket") as mock_socket:
            mock_socket.getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 80))
            ]
            resp = client.post("/api/ai/test_payload", json={
                "payload": "test",
                "target_url": "http://localhost/admin",
                "method": "GET",
            })
            data = resp.get_json()
            assert data["success"] is False
            assert "private" in data["error"].lower() or "blocked" in data["error"].lower()

    def test_payload_test_blocks_metadata_ip(self, client):
        """SSRF guard: block cloud metadata endpoint."""
        with patch("core.routes.intelligence.socket") as mock_socket:
            mock_socket.getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('169.254.169.254', 80))
            ]
            resp = client.post("/api/ai/test_payload", json={
                "payload": "test",
                "target_url": "http://169.254.169.254/latest/meta-data/",
                "method": "GET",
            })
            data = resp.get_json()
            assert data["success"] is False
