import pathlib
from pwnlib.rop import ROP


class _RopFile:
    def __init__(self, file: pathlib.Path):
        if not file.exists() or not file.is_file():
            raise ValueError(f'Illegal file path [{file}]')
        self._rop = ROP(str(file))
        self._base_address = 0

    @property
    def ret(self) -> int | None:
        return self._rop.find_gadget(['ret']).address + self.base_address

    @property
    def pop_rdi(self) -> int | None:
        return self._rop.find_gadget(['pop rdi', 'ret']).address + self.base_address

    def find(self, instructions: list) -> int | None:
        return self._rop.find_gadget(instructions).address + self.base_address

    @property
    def base_address(self) -> int:
        return self._base_address

    @base_address.setter
    def base_address(self, new_address: int):
        if self._rop.elfs[0].aslr:
            self._base_address = new_address


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

