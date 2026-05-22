from unittest.mock import patch, MagicMock

from autonet.enumeration.port_scanner import PortEnumerator
from autonet.models.host import Host


class TestPortEnumerator:
    def test_no_alive_hosts(self):
        hosts = [Host(ip="10.0.0.1", is_alive=False)]
        enumerator = PortEnumerator()
        result = enumerator.enumerate(hosts, ports="80", timeout=5, privileged=False)
        assert result == hosts

    def test_enumerate_with_alive(self):
        hosts = [Host(ip="10.0.0.1", is_alive=True)]
        enumerator = PortEnumerator()
        result = enumerator.enumerate(hosts, ports="80", timeout=5, privileged=False)
        assert len(result) == 1

    def test_os_extract_none(self):
        assert PortEnumerator._extract_os({}) is None
