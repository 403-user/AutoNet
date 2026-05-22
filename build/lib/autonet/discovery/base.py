from abc import ABC, abstractmethod
from typing import List

from autonet.models.host import Host


class BaseDiscoverer(ABC):
    @abstractmethod
    def discover(self, targets: List[str], timeout: int) -> List[Host]:
        ...
