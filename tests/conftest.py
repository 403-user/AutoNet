import pytest

from autonet.config import ScanConfig
from autonet.models.host import Host
from autonet.models.service import Service
from autonet.models.vulnerability import Vulnerability


@pytest.fixture
def sample_host():
    return Host(
        ip="192.168.1.10",
        mac="aa:bb:cc:dd:ee:ff",
        hostname="test-host",
        os_guess="Linux",
        is_alive=True,
    )


@pytest.fixture
def sample_service():
    return Service(
        port=80,
        protocol="tcp",
        state="open",
        name="http",
        product="Apache httpd",
        version="2.4.41",
        cpe="cpe:/a:apache:http_server:2.4.41",
    )


@pytest.fixture
def sample_vulnerability():
    return Vulnerability(
        cve_id="CVE-2021-41773",
        severity="HIGH",
        cvss_score=7.5,
        description="Path traversal in Apache HTTP Server 2.4.49",
        affected_product="Apache httpd",
        affected_version="2.4.41",
    )


@pytest.fixture
def sample_config():
    return ScanConfig(
        targets=["127.0.0.1"],
        ports="22,80,443",
        output_format="json",
        output_path="/tmp/test_report.json",
        rate=10,
        timeout=5,
        is_privileged=False,
    )
