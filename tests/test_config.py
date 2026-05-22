import pytest

from autonet.config import ScanConfig, build_config


class MockArgs:
    def __init__(self, targets="192.168.1.0/24", ports="top100", fmt="json",
                 output="/tmp/report.json", rate=50, timeout=30):
        self.targets = targets
        self.ports = ports
        self.format = fmt
        self.output = output
        self.rate = rate
        self.timeout = timeout


class TestScanConfig:
    def test_valid_cidr(self):
        config = ScanConfig(targets=["10.0.0.0/24"], ports="22,80")
        assert config.targets == ["10.0.0.0/24"]

    def test_valid_single_ip(self):
        config = ScanConfig(targets=["192.168.1.1"], ports="443")
        assert config.targets == ["192.168.1.1"]

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError, match="Invalid target"):
            ScanConfig(targets=["not-an-ip"], ports="80")

    def test_invalid_ports_raises(self):
        with pytest.raises(ValueError, match="Invalid port"):
            ScanConfig(targets=["10.0.0.1"], ports="abc")

    def test_invalid_rate_raises(self):
        with pytest.raises(ValueError):
            ScanConfig(targets=["10.0.0.1"], ports="80", rate=0)

    def test_top100_expands(self):
        config = ScanConfig(targets=["10.0.0.1"], ports="top100")
        assert "," in config.ports

    def test_top1000_expands(self):
        config = ScanConfig(targets=["10.0.0.1"], ports="top1000")
        assert config.ports == "1-1000"

    def test_output_format_validation(self):
        with pytest.raises(ValueError, match="Output format"):
            ScanConfig(targets=["10.0.0.1"], ports="80", output_format="xml")

    def test_build_config(self):
        args = MockArgs()
        config = build_config(args)
        assert config.targets == ["192.168.1.0/24"]
        assert config.rate == 50
