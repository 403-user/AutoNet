import asyncio
import logging
from typing import List

from autonet.config import ScanConfig
from autonet.discovery.arp import ARPDiscoverer
from autonet.discovery.ping import PingDiscoverer
from autonet.enumeration.port_scanner import PortEnumerator
from autonet.models.host import Host
from autonet.reporting.csv_reporter import CSVReporter
from autonet.reporting.json_reporter import JSONReporter
from autonet.vuln_matching.matcher import VulnMatcher

logger = logging.getLogger("autonet.scanner")


class Scanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self._hosts: List[Host] = []

    def run(self) -> List[Host]:
        self._hosts = self._discover()
        self._hosts = self._enumerate()
        self._hosts = self._match_vulns()
        return self._hosts

    def _discover(self) -> List[Host]:
        privileged = self.config.is_privileged
        logger.info(f"Discovery phase (privileged={privileged})")

        try:
            if privileged:
                discoverer = ARPDiscoverer()
                hosts = discoverer.discover(self.config.targets, self.config.timeout)
            else:
                raise PermissionError("Not root, falling back to ping discovery")
        except PermissionError:
            discoverer = PingDiscoverer()
            hosts = discoverer.discover(self.config.targets, self.config.timeout)

        alive = sum(1 for h in hosts if h.is_alive)
        logger.info(f"Discovery found {len(hosts)} hosts ({alive} alive)")
        return hosts

    def _enumerate(self) -> List[Host]:
        logger.info("Enumeration phase")
        enumerator = PortEnumerator()
        hosts = enumerator.enumerate(
            hosts=self._hosts,
            ports=self.config.ports,
            timeout=self.config.timeout,
            privileged=self.config.is_privileged,
        )
        open_ports = sum(len(h.services) for h in hosts)
        logger.info(f"Enumeration found {open_ports} open ports across {sum(1 for h in hosts if h.is_alive)} hosts")
        return hosts

    def _match_vulns(self) -> List[Host]:
        logger.info("Vulnerability matching phase")
        matcher = VulnMatcher()

        async def _run():
            return await matcher.match(self._hosts, rate=self.config.rate)

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            hosts = loop.run_until_complete(_run())
            loop.close()
        except Exception as e:
            logger.error(f"Vulnerability matching failed: {e}")
            hosts = self._hosts

        total_vulns = sum(len(h.vulnerabilities) for h in hosts)
        logger.info(f"Found {total_vulns} potential vulnerabilities")
        return hosts

    def report(self, hosts: List[Host] = None) -> None:
        hosts = hosts or self._hosts
        logger.info(f"Writing report to {self.config.output_path}")

        if self.config.output_format == "json":
            reporter = JSONReporter()
        else:
            reporter = CSVReporter()

        reporter.report(hosts, self.config.output_path)
