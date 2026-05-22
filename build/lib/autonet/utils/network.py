import ipaddress
from typing import Iterator, List


def iter_hosts(targets: List[str]) -> Iterator[str]:
    for target in targets:
        if "/" in target:
            network = ipaddress.IPv4Network(target, strict=False)
            yield from (str(ip) for ip in network.hosts())
        else:
            yield target


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return addr.is_private
    except ValueError:
        return False
