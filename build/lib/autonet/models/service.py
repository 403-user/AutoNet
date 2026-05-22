from dataclasses import dataclass
from typing import Optional


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "cpe": self.cpe,
        }
