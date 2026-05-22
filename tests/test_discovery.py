from unittest.mock import patch, MagicMock

from autonet.discovery.ping import PingDiscoverer


class TestPingDiscoverer:
    def test_discover_no_alive_hosts(self):
        discoverer = PingDiscoverer()
        hosts = discoverer.discover(["10.0.0.1"], timeout=2)
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.1"

    def test_discover_with_alive(self):
        discoverer = PingDiscoverer()
        hosts = discoverer.discover(["10.0.0.1/30"], timeout=2)
        assert len(hosts) > 0
        for h in hosts:
            assert isinstance(h.ip, str)


class TestARPDiscoverer:
    def test_imports(self):
        from autonet.discovery.arp import ARPDiscoverer
        assert ARPDiscoverer is not None
