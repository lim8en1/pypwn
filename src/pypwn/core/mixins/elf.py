import pathlib
import typing

from pwnlib.elf import ELF
from pwnlib.elf.elf import dotdict


class _ElfFile:
    @typing.overload
    def __init__(self, file: pathlib.Path, main_function_name: str): ...

    @typing.overload
    def __init__(self, file: pathlib.Path, main_function_address: int): ...

    @typing.overload
    def __init__(self, file: pathlib.Path): ...

    def __init__(self, file: pathlib.Path, main: str | int | None = None):
        if not file.exists() or not file.is_file():
            raise ValueError(f'Illegal file path [{file}]')
        self._file = ELF(str(file))

        if isinstance(main, str):
            self._main_ptr = self._file.symbols[main]
        elif isinstance(main, int):
            self._main_ptr = main
        else:
            self._main_ptr = None
        self._base_address = 0x0

    @property
    def main_ptr(self) -> int | None:
        return self._main_ptr

    @property
    def symbols(self) -> dotdict:
        return self._file.symbols

    @property
    def got(self) -> dotdict:
        return self._file.got

    @property
    def plt(self) -> dotdict:
        return self._file.plt


class ElfFileMixin:
    @typing.overload
    def __init__(self, file: pathlib.Path, main_function_name: str): ...

    @typing.overload
    def __init__(self, file: pathlib.Path, main_function_address: int): ...

    @typing.overload
    def __init__(self, file: pathlib.Path): ...

    def __init__(self, file: pathlib.Path, main: str | int | None = None):
        """
        :param file: path to the target ELF file
        :param main: name or address of the main function
        """

        self._elf_file = _ElfFile(file, main)

    @property
    def elf(self) -> _ElfFile:
        return self._elf_file
