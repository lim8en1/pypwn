import ipaddress

from loguru import logger
from pwnlib.tubes.remote import remote
from pypwn.core.abstract.target import AbstractTarget


class RemoteTarget(AbstractTarget):
    @property
    def channel(self):
        return self._process

    def reconnect(self) -> None:
        self._process = remote(self._ip.exploded, self._port)

    def __init__(self, ip: ipaddress.IPv4Address, port: int):
        super().__init__()
        self._ip = ip
        self._port = port
        logger.info(f"Starting in REMOTE mode. Target: {self._ip}:{self._port}")
        self._process = remote(self._ip.exploded, self._port)
