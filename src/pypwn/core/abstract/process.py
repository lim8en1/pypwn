import abc
from pwnlib.tubes.tube import tube

from pypwn.core.abstract.target import AbstractTarget


class AbstractProcess(abc.ABC):
    def __init__(self, target: AbstractTarget):
        self._target = target

    def __call__(self, *args, **kwargs):
        raise NotImplementedError()

    def interactive(self):
        self._target.channel.interactive()

    @property
    def channel(self) -> tube:
        return self._target.channel
