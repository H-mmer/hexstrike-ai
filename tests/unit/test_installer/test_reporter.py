import pytest
import json
from pathlib import Path
from scripts.installer.core.reporter import Reporter

class TestReporter:
    """Test reporting functionality"""

    def test_generate_html_report(self, tmp_path):
        """Test HTML report generation"""
        reporter = Reporter()
        results = {
            'installed': [
                {'name': 'nmap', 'version': '7.94', 'category': 'network', 'path': '/usr/bin/nmap'}
            ],
            'missing': [
                {'name': 'retire-js', 'package': 'retire', 'category': 'web-enhanced'}
            ],
            'total': 2
        }

        output_file = tmp_path / "report.html"
        reporter.generate_html_report(results, str(output_file))

        assert output_file.exists()
        content = output_file.read_text()
        assert 'nmap' in content
        assert 'retire-js' in content
        assert '7.94' in content

    def test_export_json(self, tmp_path):
        """Test JSON export"""
        reporter = Reporter()
        # Create 220 mock installed tools and 51 missing tools
        installed_tools = [{'name': f'tool{i}', 'version': '1.0'} for i in range(220)]
        missing_tools = [{'name': f'missing{i}', 'package': f'pkg{i}'} for i in range(51)]

        results = {
            'total': 271,
            'installed': installed_tools,
            'missing': missing_tools,
        }

        output_file = tmp_path / "results.json"
        reporter.export_json(results, str(output_file))

        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data['summary']['total'] == 271
        assert data['summary']['installed'] == 220
        assert data['summary']['missing'] == 51
        assert 'timestamp' in data
