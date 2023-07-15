import abc
from pwnlib.tubes.tube import tube


class AbstractProcess(abc.ABC):
    def __init__(self, target: tube):
        self._tube = target

    def __call__(self, *args, **kwargs):
        raise NotImplementedError()

    def interactive(self):
        self._tube.interactive()

    @property
    def channel(self):
        return self._tube
