from abc import ABC, abstractmethod
from typing import List

from autonet.models.host import Host


class BaseEnumerator(ABC):
    @abstractmethod
    def enumerate(self, hosts: List[Host], ports: str, timeout: int, privileged: bool) -> List[Host]:
        ...
