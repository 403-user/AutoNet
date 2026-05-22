from dataclasses import dataclass, field
from typing import List, Optional

from autonet.models.service import Service
from autonet.models.vulnerability import Vulnerability


@dataclass
class Host:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    services: List[Service] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    is_alive: bool = False

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "os": self.os_guess,
            "is_alive": self.is_alive,
            "services": [s.to_dict() for s in self.services],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }
