from unittest.mock import patch

from autonet.config import ScanConfig
from autonet.models.host import Host
from autonet.scanner import Scanner


class TestScanner:
    def test_scanner_initialization(self, sample_config):
        scanner = Scanner(sample_config)
        assert scanner.config == sample_config
        assert scanner._hosts == []

    @patch("autonet.scanner.PingDiscoverer")
    def test_scanner_run_no_alive(self, mock_ping, sample_config):
        mock_ping.return_value.discover.return_value = [
            Host(ip="10.0.0.1", is_alive=False)
        ]
        scanner = Scanner(sample_config)
        hosts = scanner.run()
        assert hosts is not None

    @patch("autonet.scanner.PingDiscoverer")
    def test_scanner_report_json(self, mock_ping, sample_config, tmp_path):
        mock_ping.return_value.discover.return_value = [
            Host(ip="10.0.0.1", is_alive=True)
        ]
        output = tmp_path / "report.json"
        sample_config.output_path = str(output)
        sample_config.output_format = "json"
        scanner = Scanner(sample_config)
        scanner.run()
        scanner.report()
        assert output.exists()

    @patch("autonet.scanner.PingDiscoverer")
    def test_scanner_report_csv(self, mock_ping, sample_config, tmp_path):
        mock_ping.return_value.discover.return_value = [
            Host(ip="10.0.0.1", is_alive=True)
        ]
        output = tmp_path / "report.csv"
        sample_config.output_path = str(output)
        sample_config.output_format = "csv"
        scanner = Scanner(sample_config)
        scanner.run()
        scanner.report()
        assert output.exists()
