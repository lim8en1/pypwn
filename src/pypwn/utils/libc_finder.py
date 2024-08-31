import gzip
import pathlib
import sqlite3
import typing

import requests
import validators
from loguru import logger



class LibcResult:
    def __init__(self, name: str, base: int, data: str | bytes):
        self._name = name
        self._base = base
        if isinstance(data, bytes):
            self._data = data
        elif validators.url(data):
            logger.info(f"Downloading libc from {data}")
            response = requests.get(data)
            if response.ok:
                self._data = response.content
            else:
                raise ValueError(f"Failed to download libc from {data}. Response code: {response.status_code}")
        else:
            raise ValueError("LibcResult data is of unsupported type")

    @property
    def name(self) -> str:
        return self._name

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def base(self) -> int:
        return self._base


class LibcFinder:
    FunctionList = typing.Sequence[typing.Tuple[str, int]]

    @classmethod
    @typing.overload
    def find(cls, functions: FunctionList, url: str, result_filter: typing.Callable = None) -> LibcResult | None: ...

    @classmethod
    @typing.overload
    def find(cls, functions: FunctionList, path: pathlib.Path, result_filter: typing.Callable = None) -> LibcResult | None: ...

    @classmethod
    def find(cls, functions: FunctionList,
             resource: str | pathlib.Path = pathlib.Path('/opt/libcdb/libc.db'),
             result_filter: typing.Callable = None) -> LibcResult | None:
        if isinstance(resource, pathlib.Path):
            if not resource.exists() or not resource.is_file():
                logger.critical("Failed to find specified file")
                return None
            logger.info(f"Using local libc db: {resource}")
            results = cls._find_local(resource, functions)
        else:
            validation = validators.url(resource)
            if not validation:
                logger.critical("Bad resource value")
                return None
            logger.info(f"Using remote libc db: {resource}")
            results = cls._find_remote(resource, functions)

        if result_filter is not None:
            results = result_filter(results)

        if len(results) > 0:
            # name, (data, base) = results.popitem()
            choice = 0
            keys = tuple(results.keys())
            if len(results) > 1:
                logger.warning(f"Multiple possible libc versions found.")
                for i, r in enumerate(keys):
                    print(f'{i}: {r}')
                user_input = input(f"Choose a libc to use (default: 0):")
                try:
                    choice = int(user_input)
                except ValueError:
                    pass
            if choice not in range(len(keys)):
                choice = 0
            data, base = results[keys[choice]]
            return LibcResult(keys[choice], base, data)
        return None

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

        bases = {}
        possible_choices = set()
        for libc in keys:
            _base = set()
            for sample_function_name, sample_function_address in functions:
                address = function_addresses[sample_function_name][libc]
                base = sample_function_address - address
                _base.add(base)
            if len(_base) == 1:
                bases[libc] = _base.pop()
                possible_choices.add(libc)

        results = {}

        for choice in keys:
            cursor.execute('select name,data from libc where id=?', (choice,))
            result = cursor.fetchone()
            results[result[0]] = gzip.decompress(result[1]), bases[choice]
            logger.info(
                f"possible libc: {result[0]}@{hex(bases[choice])}")
        cursor.close()
        connection.close()

        return results

    @classmethod
    def _find_remote(cls, url: str, functions: FunctionList):
        results = {}
        response = requests.post(url, json={"symbols": dict((x[0],hex(x[1])) for x in functions)})
        if response.ok:
            response_parsed = response.json()
            if len(response_parsed) > 0:
                for description in response_parsed:
                    base = functions[0][1] - int(description["symbols"][functions[0][0]], 16)
                    results[description['id']] = (description["download_url"], base)
                    logger.info(f"Possible libc: {description['id']}@{hex(base)}")

        return results
