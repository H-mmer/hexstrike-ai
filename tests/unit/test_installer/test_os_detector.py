import pytest
from unittest.mock import mock_open, MagicMock, call
from scripts.installer.core.os_detector import OSDetector, OSInfo, UnsupportedOSError

class TestOSDetector:
    """Test OS detection functionality"""

    def test_detect_kali_linux(self, monkeypatch, tmp_path):
        """Test Kali Linux detection"""
        os_release = 'NAME="Kali GNU/Linux"\nVERSION="2024.2"\nID=kali'
        monkeypatch.setattr('builtins.open', mock_open(read_data=os_release))

        detector = OSDetector()
        os_info = detector.detect_os()

        assert os_info.name == 'Kali GNU/Linux'
        assert os_info.version == '2024.2'
        assert os_info.is_kali is True
        assert os_info.is_parrot is False

    def test_detect_parrot_os(self, monkeypatch):
        """Test Parrot OS detection"""
        os_release = 'NAME="Parrot OS"\nVERSION="5.3"\nID=parrot'
        monkeypatch.setattr('builtins.open', mock_open(read_data=os_release))

        detector = OSDetector()
        os_info = detector.detect_os()

        assert os_info.name == 'Parrot OS'
        assert os_info.is_parrot is True
        assert os_info.is_kali is False

    def test_reject_ubuntu(self, monkeypatch):
        """Test rejection of Ubuntu"""
        os_release = 'NAME="Ubuntu"\nVERSION="22.04 LTS"\nID=ubuntu'
        monkeypatch.setattr('builtins.open', mock_open(read_data=os_release))

        detector = OSDetector()
        with pytest.raises(UnsupportedOSError, match="Ubuntu"):
            detector.verify_supported_os()

    def test_update_repos_success(self, monkeypatch):
        """Test apt repository update"""
        mock_run = MagicMock()
        mock_run.return_value.returncode = 0
        monkeypatch.setattr('subprocess.run', mock_run)

        detector = OSDetector()
        result = detector.update_repos()

        assert result is True
        assert mock_run.call_count == 1
