import logging
from typing import List

from scapy.all import ARP, Ether, srp

from autonet.discovery.base import BaseDiscoverer
from autonet.models.host import Host
from autonet.utils.network import iter_hosts

logger = logging.getLogger("autonet.discovery.arp")


class ARPDiscoverer(BaseDiscoverer):
    def discover(self, targets: List[str], timeout: int = 10) -> List[Host]:
        hosts: List[Host] = []
        seen = set()

        for target in targets:
            if "/" not in target:
                continue

            logger.info(f"ARP scanning {target}")
            arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
            try:
                answered, _ = srp(arp, timeout=timeout, verbose=0)
            except PermissionError:
                logger.warning("ARP scan requires root; falling back")
                raise

            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                if ip not in seen:
                    seen.add(ip)
                    hosts.append(Host(ip=ip, mac=mac, is_alive=True))

        for ip in iter_hosts(targets):
            if "/" not in ip and ip not in seen:
                seen.add(ip)
                hosts.append(Host(ip=ip))

        return hosts
