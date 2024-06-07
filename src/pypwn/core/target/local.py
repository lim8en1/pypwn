import pathlib

from loguru import logger
from pwnlib.tubes.process import process
from pypwn.core.abstract.target import AbstractTarget
from pypwn.utils.gdb_wrapper import GdbWrapper


class LocalTarget(AbstractTarget):
    @property
    def channel(self):
        return self._process

    def reconnect(self) -> None:
        self._process = process(self._args)

    def __init__(self, target_file: pathlib.Path, args: list = None):
        super().__init__()
        if not target_file.exists() or not target_file.is_file():
            raise ValueError(f'Illegal file path [{target_file}]')

        if args is None:
            args = []

        self._target_file = str(target_file.absolute())
        self._args = [self._target_file]
        self._args.extend(args)
        logger.info(f"Starting in LOCAL mode. Target: {self._target_file}")
        self._process = process(self._args)

    def debugger(self) -> GdbWrapper:
        return GdbWrapper(self._process.proc.pid)

