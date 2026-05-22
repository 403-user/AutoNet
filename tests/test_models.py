from autonet.models.host import Host
from autonet.models.service import Service
from autonet.models.vulnerability import Vulnerability


class TestHost:
    def test_default_fields(self):
        host = Host(ip="10.0.0.1")
        assert host.ip == "10.0.0.1"
        assert host.mac is None
        assert host.services == []
        assert host.vulnerabilities == []
        assert host.is_alive is False

    def test_to_dict(self, sample_host):
        d = sample_host.to_dict()
        assert d["ip"] == "192.168.1.10"
        assert d["mac"] == "aa:bb:cc:dd:ee:ff"
        assert d["is_alive"] is True


class TestService:
    def test_default_fields(self):
        svc = Service(port=22)
        assert svc.protocol == "tcp"
        assert svc.state == "open"

    def test_to_dict(self, sample_service):
        d = sample_service.to_dict()
        assert d["port"] == 80
        assert d["name"] == "http"
        assert d["product"] == "Apache httpd"


class TestVulnerability:
    def test_to_dict(self, sample_vulnerability):
        d = sample_vulnerability.to_dict()
        assert d["cve_id"] == "CVE-2021-41773"
        assert d["severity"] == "HIGH"
        assert d["cvss_score"] == 7.5
