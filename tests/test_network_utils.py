from autonet.utils.network import iter_hosts, is_private_ip


class TestIterHosts:
    def test_single_ip(self):
        hosts = list(iter_hosts(["10.0.0.1"]))
        assert hosts == ["10.0.0.1"]

    def test_cidr_range(self):
        hosts = list(iter_hosts(["10.0.0.0/30"]))
        assert "10.0.0.1" in hosts
        assert "10.0.0.2" in hosts
        assert "10.0.0.0" not in hosts
        assert "10.0.0.3" not in hosts

    def test_mixed(self):
        hosts = list(iter_hosts(["10.0.0.1", "10.0.0.0/31"]))
        assert "10.0.0.1" in hosts


class TestIsPrivateIp:
    def test_private(self):
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("172.16.0.1") is True

    def test_public(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
