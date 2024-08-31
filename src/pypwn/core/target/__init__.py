import ipaddress
import pathlib

from pypwn.core.mixins.libc import LibcMixin
from pypwn.core.mixins.rop import RopMixin
from pypwn.core.mixins.elf import ElfFileMixin
from pypwn.core.target.local import LocalTarget
from pypwn.core.target.remote import RemoteTarget


class GenericLocalTarget(LocalTarget, ElfFileMixin, RopMixin, LibcMixin):
    def __init__(self,
                 target_file: pathlib.Path, args: list | None = None,
                 libc: str | pathlib.Path | None = None,
                 main: str | int | None = None,
                 illegal_symbols: set | None = None):
        if args is None:
            args = []
        LocalTarget.__init__(self, target_file, args, illegal_symbols=illegal_symbols)
        ElfFileMixin.__init__(self, target_file, main)
        RopMixin.__init__(self, target_file)
        LibcMixin.__init__(self, libc)


class GenericRemoteTarget(RemoteTarget, ElfFileMixin, RopMixin, LibcMixin):
    def __init__(self,
                 ip: ipaddress.IPv4Address,
                 port: int,
                 target_file: pathlib.Path,
                 libc: str | pathlib.Path | None = None,
                 main: str | int | None = None,
                 illegal_symbols: set | None = None):
        RemoteTarget.__init__(self, ip, port, illegal_symbols=illegal_symbols)
        ElfFileMixin.__init__(self, target_file, main)
        RopMixin.__init__(self, target_file)
        LibcMixin.__init__(self, libc)
