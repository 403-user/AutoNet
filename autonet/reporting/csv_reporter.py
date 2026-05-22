import csv
import logging
from typing import List

from autonet.models.host import Host
from autonet.reporting.base import BaseReporter

logger = logging.getLogger("autonet.reporting.csv")


class CSVReporter(BaseReporter):
    def report(self, hosts: List[Host], path: str) -> None:
        fieldnames = [
            "ip", "mac", "hostname", "port", "protocol", "service_name",
            "product", "version", "cve_id", "severity", "cvss_score", "description",
        ]
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for host in hosts:
                if not host.services:
                    writer.writerow({
                        "ip": host.ip,
                        "mac": host.mac or "",
                        "hostname": host.hostname or "",
                        "port": "",
                        "protocol": "",
                        "service_name": "",
                        "product": "",
                        "version": "",
                        "cve_id": "",
                        "severity": "",
                        "cvss_score": "",
                        "description": "",
                    })
                for svc in host.services:
                    if host.vulnerabilities:
                        for vuln in host.vulnerabilities:
                            writer.writerow({
                                "ip": host.ip,
                                "mac": host.mac or "",
                                "hostname": host.hostname or "",
                                "port": svc.port,
                                "protocol": svc.protocol,
                                "service_name": svc.name or "",
                                "product": svc.product or "",
                                "version": svc.version or "",
                                "cve_id": vuln.cve_id,
                                "severity": vuln.severity or "",
                                "cvss_score": vuln.cvss_score or "",
                                "description": vuln.description or "",
                            })
                    else:
                        writer.writerow({
                            "ip": host.ip,
                            "mac": host.mac or "",
                            "hostname": host.hostname or "",
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "service_name": svc.name or "",
                            "product": svc.product or "",
                            "version": svc.version or "",
                            "cve_id": "",
                            "severity": "",
                            "cvss_score": "",
                            "description": "",
                        })
        logger.info(f"CSV report written to {path}")
