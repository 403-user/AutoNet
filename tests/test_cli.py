import pytest

from autonet.cli import create_parser


class TestCLI:
    def test_parser_creates_args(self):
        parser = create_parser()
        args = parser.parse_args(["--targets", "192.168.1.0/24"])
        assert args.targets == "192.168.1.0/24"
        assert args.ports == "top100"
        assert args.format == "json"
        assert args.output == "autonet_report.json"
        assert args.rate == 50
        assert args.timeout == 30

    def test_parser_custom_args(self):
        parser = create_parser()
        args = parser.parse_args([
            "--targets", "10.0.0.1,10.0.0.2",
            "--ports", "22,80,443",
            "--format", "csv",
            "--output", "/tmp/scan.csv",
            "--rate", "100",
            "--timeout", "60",
            "--verbose",
        ])
        assert args.targets == "10.0.0.1,10.0.0.2"
        assert args.ports == "22,80,443"
        assert args.format == "csv"
        assert args.output == "/tmp/scan.csv"
        assert args.rate == 100
        assert args.timeout == 60
        assert args.verbose is True

    def test_parser_requires_targets(self):
        parser = create_parser()
        import io, sys
        with pytest.raises(SystemExit):
            parser.parse_args([])
