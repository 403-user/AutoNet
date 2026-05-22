import asyncio
import logging
import subprocess
from typing import List, Set

from autonet.discovery.base import BaseDiscoverer
from autonet.models.host import Host
from autonet.utils.network import iter_hosts

logger = logging.getLogger("autonet.discovery.ping")

_PROBE_PORTS = [22, 80, 443, 445, 8080, 8443, 3389, 5900]


class PingDiscoverer(BaseDiscoverer):
    def discover(self, targets: List[str], timeout: int = 10) -> List[Host]:
        ips = list(iter_hosts(targets))
        if not ips:
            return []

        alive_ips = self._nmap_ping_scan(targets, timeout)
        if alive_ips is None:
            alive_ips = self._tcp_probe_scan(ips, timeout)

        hosts = [Host(ip=ip, is_alive=ip in alive_ips) for ip in ips]
        return hosts

    def _nmap_ping_scan(self, targets: List[str], timeout: int) -> Set[str] | None:
        try:
            target_str = " ".join(targets)
            result = subprocess.run(
                ["nmap", "-sn", "-T4", "--host-timeout", f"{timeout}s", target_str],
                capture_output=True,
                text=True,
                timeout=timeout + 10,
            )
            alive: Set[str] = set()
            for line in result.stdout.splitlines():
                if "Nmap scan report for" in line:
                    parts = line.split()
                    ip = parts[-1].strip("()")
                    alive.add(ip)
            if alive:
                logger.info(f"nmap -sn detected {len(alive)} alive hosts")
                return alive
            return None
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug(f"nmap -sn unavailable or timed out: {e}")
            return None

    def _tcp_probe_scan(self, ips: List[str], timeout: int) -> Set[str]:
        alive: Set[str] = set()

        async def _probe(ip: str) -> str | None:
            for port in _PROBE_PORTS:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=max(1, timeout // 4),
                    )
                    writer.close()
                    await writer.wait_closed()
                    return ip
                except (OSError, asyncio.TimeoutError):
                    continue
            return None

        async def _run():
            sem = asyncio.Semaphore(100)

            async def check(ip: str):
                async with sem:
                    return await _probe(ip)

            tasks = [check(ip) for ip in ips]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    alive.add(result)
            return alive

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_run())
            loop.close()
        except Exception as e:
            logger.error(f"TCP probe discovery error: {e}")

        return alive
