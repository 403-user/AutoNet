import asyncio
import logging
import socket
from typing import List

from autonet.discovery.base import BaseDiscoverer
from autonet.models.host import Host
from autonet.utils.network import iter_hosts

logger = logging.getLogger("autonet.discovery.ping")

_PROBE_PORTS = [22, 80, 443, 445]


class PingDiscoverer(BaseDiscoverer):
    def discover(self, targets: List[str], timeout: int = 10) -> List[Host]:
        ips = list(iter_hosts(targets))
        hosts: List[Host] = []

        async def _probe(ip: str) -> bool:
            for port in _PROBE_PORTS:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=max(1, timeout // 4),
                    )
                    writer.close()
                    await writer.wait_closed()
                    return True
                except (OSError, asyncio.TimeoutError):
                    continue
            return False

        async def _run():
            sem = asyncio.Semaphore(100)
            results = []

            async def check(ip: str):
                async with sem:
                    alive = await _probe(ip)
                    host = Host(ip=ip, is_alive=alive)
                    if alive:
                        logger.debug(f"Host {ip} is alive")
                    return host

            tasks = [check(ip) for ip in ips]
            for coro in asyncio.as_completed(tasks):
                results.append(await coro)
            return results

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            hosts = loop.run_until_complete(_run())
            loop.close()
        except Exception as e:
            logger.error(f"Ping discovery error: {e}")

        return hosts
