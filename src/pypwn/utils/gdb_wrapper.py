import pathlib
import re
from typing import overload

from pwnlib import gdb
from loguru import logger


class GdbWrapper:
    def __init__(self, target: int | pathlib.Path | str, additional_args: str | None = None):
        self._debugger = None
        kwargs = {}
        if additional_args:
            kwargs['gdb_args'] = additional_args.split()
        if isinstance(target, int):
            logger.debug(f'Attaching to pid {target}')
            pid, debugger = gdb.attach(target, api=True, **kwargs)
            self._debugger = GdbApi(debugger)
        elif isinstance(target, pathlib.Path):
            logger.debug(f'Starting {target.absolute()} in gdb')
            proc = gdb.debug(str(target.absolute()), api=True, **kwargs)
            self._debugger = GdbApi(proc.gdb)
        elif isinstance(target, str):
            logger.debug(f'Starting {target} in gdb')
            proc = gdb.debug(target, api=True, **kwargs)
            self._debugger = GdbApi(proc.gdb)

    def __enter__(self):
        if self._debugger:
            return self._debugger
        raise ValueError()

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.debug(f'Closing gdb')
        self._debugger.quit()


class GdbApi:
    def __init__(self, debugger: gdb.Gdb):
        self._debugger = debugger
        self._threads = {}
        self._update_thread_status()

    def _update_thread_status(self):
        responses = self._debugger.execute('info threads', to_string=True).strip().split('\n')[1:]
        for response in responses:
            id = re.search(r'^\*?\s+(\d+)', response)[1]
            self._threads[int(id)] = not 'running' in response

    def api(self):
        return self._debugger

    def resume(self):
        self._debugger.execute('continue')

    def interrupt(self):
        self._debugger.interrupt_and_wait()

    def read_value(self, value: str, thread_id: int = 1, modifier: str = 'x') -> None | str:
        self._update_thread_status()
        if thread_id in self._threads and self._threads[thread_id]:
            self._debugger.execute(f'thread {thread_id}')
            value = self._debugger.execute(f"print/{modifier} {value}", to_string=True)
            return value.split("=", maxsplit=1)[1].strip()
        return None

    def read_memory(self, address: str, count: int, thread_id: int = 1, modifier: str = 'b') -> None | list:
        self._update_thread_status()
        if thread_id in self._threads and self._threads[thread_id]:
            self._debugger.execute(f'thread {thread_id}')
            values = self._debugger.execute(f"x/{count}{modifier}x {address}", to_string=True).strip()
            result = list()
            for value in values.split('\n'):
                bytes = value.split(':')[1].strip().split()
                for byte in bytes:
                    result.append(int(byte, 16))
            return result
        return None

    def quit(self):
        self._debugger.quit()

    def execute(self, gdb_command: str) -> str:
        return self._debugger.execute(gdb_command, to_string=True)

    @overload
    def breakpoint(self, target_address: int): ...

    @overload
    def breakpoint(self, target_name: str): ...

    def breakpoint(self, target: int | str):
        if isinstance(target, int):
            target = f"*{hex(target)}"
        logger.info(f"Creating breakpoint at: {target}")
        self._debugger.execute(f"break {target}")
