import abc
from typing import Optional


class AbstractModule(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def execute(cls, *args, **kwargs) -> Optional:
        raise NotImplementedError()
