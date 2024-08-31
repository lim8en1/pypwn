import enum
import typing

from core.abstract.process import AbstractProcess
from pypwn.core.abstract.module import AbstractModule
from pypwn.core.protocols import ITarget, IElfFile
from loguru import logger


class Method(enum.Enum):
    SymbolTable = enum.auto()
    PLT = enum.auto()
    GOT = enum.auto()


class FindFunction(AbstractModule):
    class __TargetType(ITarget, IElfFile): ...

    @classmethod
    def execute(cls, process: AbstractProcess, function_name: typing.Union[typing.AnyStr, typing.List[typing.AnyStr]],
                method: Method = Method.SymbolTable, find_all: bool = False, *args, **kwargs) -> typing.Any:
        logger.info(f"Running {cls.__name__} module")
        if not isinstance(function_name, list):
            function_name = (function_name,)

        results = {}
        if find_all:
            for function in function_name:
                address = cls.execute(process, function, method)
                if address:
                    results[function] = address
            return results
        logger.info(f"Looking for [{function_name}] function address.")
        address = None
        if method == Method.SymbolTable:
            logger.info("Checking out the symbol table")
            container = process.target.elf.symbols
        elif method == Method.PLT:
            logger.info("Checking out the procedure linkage table")
            container = process.target.elf.plt
        elif method == Method.GOT:
            logger.info("Checking out the global offset table")
            container = process.target.elf.got
        else:
            logger.critical(f"Method not supported")
            return address

        for name in function_name:
            try:
                address = container[name]
                logger.success(f"Found: {name}@{hex(address)}")
                return name, address
            except KeyError:
                pass
        logger.critical(f"No address for any functions provided found")
        return None
