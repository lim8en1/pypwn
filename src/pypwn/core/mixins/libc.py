import functools
import pathlib
import tempfile

import typing
from loguru import logger
from pwnlib.elf import ELF

from pypwn.utils.libc_finder import LibcResult


class _LibcFile:
    FunctionList = typing.Sequence[typing.Tuple[str, int]]

    def __init__(self, libc: str | pathlib.Path | None = None):
        self._libc_version_detected = False
        if isinstance(libc, str):
            # TODO: add load from db
            raise NotImplementedError()
        elif isinstance(libc, pathlib.Path):
            if not libc.exists() or not libc.is_file():
                raise ValueError(f'Illegal file path [{libc}]')
            self._libc = ELF(str(libc))
        else:
            self._libc_version_detected = False
            self._libc = None
        self._libc_base_address = 0x0

    @staticmethod
    def _requires_libc(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            if not self._libc_version_detected:
                logger.critical("Libc is not initialized")
                return None
            return func(self, *args, **kwargs)

        return wrapper

    @_requires_libc
    def find_string(self, string: bytes) -> int | None:
        return next(self._libc.search(string), None)

    @_requires_libc
    def find_symbol(self, name: str) -> int | None:
        return self._libc.symbols.get(name, None)

    @_requires_libc
    def update_base_address(self, functions: FunctionList):
        function_name, leaked_address = functions[0]
        address = self._libc.symbols[function_name]
        base = leaked_address - address
        self._libc.address = base

        if base % 0x100:
            logger.warning(f"libc@{hex(base)}")
        else:
            logger.success(f"libc@{hex(base)}")
        return True

    def set_libc(self, libc: LibcResult):
        tmp_file = tempfile.NamedTemporaryFile('wb')
        logger.info(f"Saving libc data to {tmp_file.name}")
        tmp_file.write(libc.data)
        tmp_file.flush()
        logger.info(f"Parsing libc symbols...")
        self._libc = ELF(tmp_file.name)
        self._libc.address = libc.base
        self._libc_version_detected = True


class LibcMixin:
    @typing.overload
    def __init__(self, libc_path: pathlib.Path): ...

    @typing.overload
    def __init__(self, libc_name: str): ...

    @typing.overload
    def __init__(self): ...

    def __init__(self, libc: str | pathlib.Path | None = None):
        self._libc_file = _LibcFile(libc)

    @property
    def libc(self) -> _LibcFile:
        return self._libc_file

