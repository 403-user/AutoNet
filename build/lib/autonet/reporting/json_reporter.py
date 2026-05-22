import json
import logging
from typing import List

from autonet.models.host import Host
from autonet.reporting.base import BaseReporter

logger = logging.getLogger("autonet.reporting.json")


class JSONReporter(BaseReporter):
    def report(self, hosts: List[Host], path: str) -> None:
        data = {
            "scan_metadata": {
                "hosts_scanned": len(hosts),
                "hosts_alive": sum(1 for h in hosts if h.is_alive),
                "total_vulnerabilities": sum(len(h.vulnerabilities) for h in hosts),
            },
            "hosts": [h.to_dict() for h in hosts],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"JSON report written to {path}")
