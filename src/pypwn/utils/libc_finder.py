import pathlib
import sqlite3
import typing
from collections import Counter
import validators
from loguru import logger


class _LibcResult:
    def __init__(self, ):
        pass


class LibcFinder:
    FunctionList = typing.Sequence[typing.Tuple[str, int]]

    @classmethod
    @typing.overload
    def find(cls, url: str, functions: FunctionList, result_filter: typing.Callable = None) -> _LibcResult | None: ...

    @classmethod
    @typing.overload
    def find(cls, path: pathlib.Path, functions: FunctionList, result_filter: typing.Callable = None) -> _LibcResult | None: ...

    @classmethod
    def find(cls, resource: str | pathlib.Path, functions: FunctionList,
             result_filter: typing.Callable = None) -> _LibcResult | None:
        validation = validators.url(resource)
        if validation:
            logger.info(f"Using remote libc db: {resource}")
            results = cls._find_remote(resource, functions)
        elif isinstance(resource, pathlib.Path):
            if not resource.exists() or not resource.is_file():
                logger.critical("Failed to find specified file")
                return None
            logger.info(f"Using local libc db: {resource}")
            results = cls._find_local(resource, functions)
        else:
            logger.critical("Bad resource value")
            return None

        if result_filter is not None:
            return result_filter(results)
        return results

    @classmethod
    def _find_local(cls, path: pathlib.Path, functions: FunctionList):
        connection = sqlite3.connect(path)
        cursor = connection.cursor()
        function_addresses = {}

        for function_name, function_address in functions:
            cursor.execute('select id from symbol where name=?', (function_name,))
            result = cursor.fetchone()[0]
            cursor.execute(
                'select libc_id, address from symbol2address where (symbol_id = ?) and ((address & 0xFFF) = ?)',
                (result, function_address & 0xFFF)
            )
            values = cursor.fetchall()
            function_addresses[function_name] = dict((x[0], x[1]) for x in values)

        keys = set(function_addresses[functions[0][0]])
        for function in functions[1:]:
            function_name = function[0]
            keys.intersection_update(function_addresses[function_name])

        possible_choices = Counter()
        bases = {}
        for libc in keys:
            sample_function_name, sample_function_address = functions[0]
            address = function_addresses[sample_function_name][libc]
            base = sample_function_address - address
            bases[libc] = base
        results = {}

        for choice in possible_choices:
            cursor.execute('select name,data from libc where id=?', (choice,))
            result = cursor.fetchone()
            results[result[0]] = result[1], bases[choice], (possible_choices[choice] + 1) / len(functions)
            logger.info(
                f"possible libc: {result[0]}@{hex(bases[choice])}, confidence {(possible_choices[choice] + 1) / len(functions)}")
        cursor.close()
        connection.close()
        return results

    @classmethod
    def _find_remote(cls, url: str, functions: FunctionList):
        raise NotImplementedError()
