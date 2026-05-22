import asyncio
import logging
from typing import List, Optional

import aiohttp

from autonet.models.host import Host
from autonet.models.service import Service
from autonet.models.vulnerability import Vulnerability
from autonet.vuln_matching.base import BaseVulnMatcher

logger = logging.getLogger("autonet.vuln_matching.cve_lookup")

VULNERS_API = "https://vulners.com/api/v3/burp/software/"
MAX_RETRIES = 3
BASE_DELAY = 1.0


class CVELookupMatcher(BaseVulnMatcher):
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self):
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={"User-Agent": "AutoNet/0.1.0"},
                timeout=aiohttp.ClientTimeout(total=15),
            )

    async def _query_vulners(self, product: str, version: str) -> List[Vulnerability]:
        await self._ensure_session()
        params = {"software": product, "version": version}

        for attempt in range(MAX_RETRIES):
            try:
                async with self.session.get(VULNERS_API, params=params) as resp:
                    if resp.status == 429:
                        retry_after = int(resp.headers.get("Retry-After", BASE_DELAY))
                        await asyncio.sleep(retry_after * (attempt + 1))
                        continue
                    if resp.status != 200:
                        logger.warning(f"Vulners API returned {resp.status} for {product} {version}")
                        return []
                    data = await resp.json()
                    return self._parse_vulners_response(data, product, version)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                delay = BASE_DELAY * (2 ** attempt)
                logger.debug(f"Vulners API error (attempt {attempt + 1}): {e}, retrying in {delay}s")
                await asyncio.sleep(delay)

        logger.warning(f"Vulners API failed after {MAX_RETRIES} retries for {product} {version}")
        return []

    @staticmethod
    def _parse_vulners_response(data: dict, product: str, version: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        search = data.get("data", {}).get("search", [])
        for entry in search:
            source = entry.get("_source", {})
            cve_id = source.get("id", "")
            if not cve_id.startswith("CVE-"):
                continue
            vuln = Vulnerability(
                cve_id=cve_id,
                severity=source.get("cvss", {}).get("severity"),
                cvss_score=source.get("cvss", {}).get("score"),
                description=source.get("description", ""),
                affected_product=product,
                affected_version=version,
            )
            vulns.append(vuln)
        return vulns

    async def _process_service(self, service: Service) -> List[Vulnerability]:
        if not service.product or not service.version:
            return []
        return await self._query_vulners(service.product, service.version)

    async def match(self, hosts: List[Host], rate: int = 10) -> List[Host]:
        await self._ensure_session()
        sem = asyncio.Semaphore(rate)

        async def handle_service(service: Service) -> List[Vulnerability]:
            async with sem:
                return await self._process_service(service)

        tasks = []
        service_map: List[tuple] = []
        for host in hosts:
            for svc in host.services:
                if svc.product and svc.version:
                    tasks.append(handle_service(svc))
                    service_map.append((host, svc))

        if not tasks:
            logger.info("No services with versions found for CVE matching")
            return hosts

        logger.info(f"Querying Vulners for {len(tasks)} services (rate: {rate})")
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (host, svc), vulns in zip(service_map, results):
            if isinstance(vulns, Exception):
                logger.debug(f"Vuln lookup failed for {svc.product} {svc.version}: {vulns}")
                continue
            host.vulnerabilities.extend(vulns)
            host.vulnerabilities = list({v.cve_id: v for v in host.vulnerabilities}.values())

        if self.session and not self.session.closed:
            await self.session.close()

        return hosts
