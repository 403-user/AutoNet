import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import List


PORT_PATTERNS = {
    "top100": "20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,8080,8443,9000,27017",
    "top1000": "1-1000",
}


@dataclass
class ScanConfig:
    targets: List[str] = field(default_factory=list)
    ports: str = "top100"
    output_format: str = "json"
    output_path: str = "autonet_report.json"
    rate: int = 50
    timeout: int = 30
    is_privileged: bool = False

    def __post_init__(self):
        self.is_privileged = os.geteuid() == 0
        self.ports = PORT_PATTERNS.get(self.ports, self.ports)
        self._validate()

    def _validate(self):
        for target in self.targets:
            try:
                if "/" in target:
                    ipaddress.IPv4Network(target, strict=False)
                else:
                    ipaddress.IPv4Address(target)
            except ValueError as e:
                raise ValueError(f"Invalid target '{target}': {e}")
        port_range = r"^(\d+(-\d+)?)(,\d+(-\d+)?)*$"
        if not re.match(port_range, self.ports):
            raise ValueError(f"Invalid port specification: '{self.ports}'")
        if self.rate < 1:
            raise ValueError("Rate must be >= 1")
        if self.timeout < 1:
            raise ValueError("Timeout must be >= 1")
        if self.output_format not in ("json", "csv"):
            raise ValueError("Output format must be 'json' or 'csv'")


def build_config(args) -> ScanConfig:
    raw = args.targets
    targets = []
    for part in raw.split(","):
        part = part.strip()
        if "/" in part:
            network = ipaddress.IPv4Network(part, strict=False)
            targets.append(str(network))
        else:
            targets.append(part)
    return ScanConfig(
        targets=targets,
        ports=args.ports,
        output_format=args.format,
        output_path=args.output,
        rate=args.rate,
        timeout=args.timeout,
    )
