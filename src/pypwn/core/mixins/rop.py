import pathlib
from pwnlib.rop import ROP


class _RopFile:
    def __init__(self, file: pathlib.Path):
        if not file.exists() or not file.is_file():
            raise ValueError(f'Illegal file path [{file}]')
        self._rop = ROP(str(file))

    @property
    def ret(self) -> int | None:
        return self._rop.find_gadget(['ret']).address

    @property
    def pop_rdi(self) -> int | None:
        return self._rop.find_gadget(['pop rdi', 'ret']).address

    def find(self, instructions: list) -> int | None:
        return self._rop.find_gadget(instructions).address


class RopMixin:
    def __init__(self, file: pathlib.Path):
        """
        :param file: path to the target ELF file
        """
        if not file.exists() or not file.is_file():
            raise ValueError(f'Illegal file path [{file}]')

        self._rop_file = _RopFile(file)

    @property
    def rop(self) -> _RopFile:
        return self._rop_file

