import threading
from typing import Optional
from loguru import logger

from pwnlib.util.cyclic import cyclic, cyclic_find

from pypwn.core.abstract.module import AbstractModule
from pypwn.core.protocols import IDebuggable, ITarget


class FindOffset(AbstractModule):
    thread_timeout = 5

    class __TargetType(ITarget, IDebuggable): ...

    @classmethod
    def execute(cls, target: __TargetType, max_offset: int, *args, **kwargs) -> Optional:
        r = []

        def _signal_handler(event):
            logger.success(f'Stop signal caught')
            if event.stop_signal == 'SIGSEGV':
                logger.info('Received SIGSEGV')
            else:
                logger.warning(f'Received another signal: {event.stop_signal}')
            result = debugger.read_value('$rsp', to_string=True)
            value = int(result.split('\t')[1].strip(), base=16)
            offset = cyclic_find(value)
            if offset != -1:
                logger.success(f'Found offset: {hex(offset)}')
                r.append(offset)
                sighandler_done.set()

        logger.info(f"Running {cls.__name__} module")
        logger.info('Looking for the offset')
        logger.info('Starting up the debugger...')
        with target.debugger() as debugger:
            sighandler_done = threading.Event()
            logger.info(f'Setting up signal callback')
            debugger.api().events.stop.connect(_signal_handler)
            debugger.resume()

            logger.info(f'Generating payload, size={hex(max_offset)}')
            payload = cyclic(max_offset)
            logger.info(f'Running main...')
            target.process(payload)
            if not sighandler_done.wait(timeout=cls.thread_timeout):
                logger.critical("Failed to trigger overflow")
            logger.info("Cleaning up gdb")
            debugger.resume()
        if sighandler_done.is_set():
            return r.pop()
        else:
            return None
