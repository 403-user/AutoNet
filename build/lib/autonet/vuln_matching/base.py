from abc import ABC, abstractmethod
from typing import List

from autonet.models.host import Host


class BaseVulnMatcher(ABC):
    @abstractmethod
    async def match(self, hosts: List[Host], rate: int = 10) -> List[Host]:
        ...
