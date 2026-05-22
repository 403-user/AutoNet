import logging
from typing import Dict, List

import nmap

from autonet.enumeration.base import BaseEnumerator
from autonet.models.host import Host
from autonet.models.service import Service

logger = logging.getLogger("autonet.enumeration.port_scanner")


class PortEnumerator(BaseEnumerator):
    def enumerate(
        self,
        hosts: List[Host],
        ports: str = "top100",
        timeout: int = 30,
        privileged: bool = False,
    ) -> List[Host]:
        scanner = nmap.PortScanner()

        scan_args = "-sV"  # always do version detection
        if privileged:
            scan_args += " -sS"  # SYN stealth scan
        else:
            scan_args += " -sT"  # TCP connect scan

        scan_args += f" --host-timeout {timeout * 1000}"

        targets = [h.ip for h in hosts if h.is_alive]
        if not targets:
            logger.warning("No alive hosts to scan")
            return hosts

        target_str = " ".join(targets)
        logger.info(f"Scanning {len(targets)} hosts on ports {ports}")
        logger.debug(f"nmap args: {scan_args}, targets: {target_str}")

        try:
            scanner.scan(hosts=target_str, ports=ports, arguments=scan_args, timeout=timeout)
        except Exception as e:
            logger.error(f"nmap scan failed: {e}")
            return hosts

        host_map: Dict[str, Host] = {h.ip: h for h in hosts}

        for ip, result in scanner.all_hosts():
            host = host_map.get(ip)
            if host is None:
                continue

            host.hostname = result.get("hostname", host.hostname)
            host.os_guess = self._extract_os(result)

            for proto in result.get("all_protocols()", result.get("all_protocols", [])):
                ports_data = result.get(proto, {})
                for port, port_info in ports_data.items():
                    service = Service(
                        port=int(port),
                        protocol=proto,
                        state=port_info.get("state", "unknown"),
                        name=port_info.get("name"),
                        product=port_info.get("product"),
                        version=port_info.get("version"),
                        cpe=port_info.get("cpe", port_info.get("cpe2")),
                    )
                    host.services.append(service)

        return hosts

    @staticmethod
    def _extract_os(result) -> str | None:
        if "osmatch" in result and result["osmatch"]:
            return result["osmatch"][0].get("name")
        if "osclass" in result and result["osclass"]:
            return result["osclass"][0].get("osfamily")
        return None
