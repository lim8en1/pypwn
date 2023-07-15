import abc

from pwnlib.context import context
from pwn import p64


class AbstractTarget(abc.ABC):
    @abc.abstractmethod
    def reconnect(self) -> None:
        raise NotImplementedError()

    def __init__(self, illegal_symbols: set = None):
        context.log_level = 'error'

        if illegal_symbols is None:
            illegal_symbols = set()
        self._illegal_symbols = illegal_symbols

    def generate_payload(self, payload: bytes, offset: int = 0, leave: bool = False, canary: int | None = None) -> bytes:
        # TODO: add 32-bit support
        result = (
            self._generate_filler(offset) +
            self._canary(canary) +
            self._leave(leave) +
            payload
        )

        if any(symbol in self._illegal_symbols for symbol in result):
            raise ValueError('Illegal symbol in generated payload')

        return result

    def _generate_filler(self, offset: int) -> bytes:
        return b'A' * offset

    def _canary(self, canary: int | None) -> bytes:
        return p64(canary) if canary else b''

    def _leave(self, leave: bool) -> bytes:
        return b'B' * 8 if leave else b''
