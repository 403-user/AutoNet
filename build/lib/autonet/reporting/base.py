from abc import ABC, abstractmethod
from typing import List

from autonet.models.host import Host


class BaseReporter(ABC):
    @abstractmethod
    def report(self, hosts: List[Host], path: str) -> None:
        ...
