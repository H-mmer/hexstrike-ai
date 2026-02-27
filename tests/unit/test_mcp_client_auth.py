# tests/unit/test_mcp_client_auth.py
"""Tests for MCP client API key header."""
import os
from unittest.mock import patch, MagicMock


def test_client_sends_api_key_header(monkeypatch):
    monkeypatch.setenv("HEXSTRIKE_API_KEY", "my-secret")
    # Prevent actual connection attempt
    with patch("hexstrike_mcp_tools.client.requests.Session") as MockSession:
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "ok"}
        mock_resp.raise_for_status = MagicMock()
        mock_session.get.return_value = mock_resp
        mock_session.post.return_value = mock_resp
        MockSession.return_value = mock_session

        from importlib import reload
        import hexstrike_mcp_tools.client as client_mod
        reload(client_mod)

        c = client_mod.HexStrikeClient("http://127.0.0.1:8888")
        # Verify the session has the API key header
        mock_session.headers.update.assert_any_call({"X-API-Key": "my-secret"})


def test_client_no_api_key_no_header(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_API_KEY", raising=False)
    with patch("hexstrike_mcp_tools.client.requests.Session") as MockSession:
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "ok"}
        mock_resp.raise_for_status = MagicMock()
        mock_session.get.return_value = mock_resp
        MockSession.return_value = mock_session

        from importlib import reload
        import hexstrike_mcp_tools.client as client_mod
        reload(client_mod)

        c = client_mod.HexStrikeClient("http://127.0.0.1:8888")
        # No API key header call expected
        if mock_session.headers.update.called:
            for call in mock_session.headers.update.call_args_list:
                assert "X-API-Key" not in call[0][0]
