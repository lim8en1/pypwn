import typing

from pypwn.core.mixins.elf import _ElfFile
from pypwn.core.mixins.libc import _LibcFile
from pypwn.core.mixins.rop import _RopFile
from pypwn.utils.gdb_wrapper import GdbWrapper


class ILibc(typing.Protocol):
    @property
    def libc(self) -> _LibcFile: ...


class IRop(typing.Protocol):
    @property
    def rop(self) -> _RopFile: ...


class ITarget(typing.Protocol):
    def generate_payload(self, payload: bytes, offset: int = 0, leave: bool = False,
                         canary: int | None = None) -> bytes: ...

    def reconnect(self) -> None: ...


class IElfFile(typing.Protocol):
    @property
    def elf(self) -> _ElfFile: ...


class IDebuggable(typing.Protocol):
    def debugger(self) -> GdbWrapper: ...

    def reconnect(self) -> None: ...
