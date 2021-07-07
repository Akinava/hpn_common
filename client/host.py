# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


import asyncio
import signal
from settings import logger
from connection import Connection
from net_pool import NetPool
from package_parser import Parser
import utilit


class UDPHost:
    def __init__(self, handler, protocol):
        logger.info('')
        self.handler = handler
        self.protocol = Parser.recovery_contraction(protocol)
        self.net_pool = NetPool()
        self.__set_posix_handler()

    def __set_posix_handler(self):
        signal.signal(signal.SIGUSR1, self.__handle_posix_signal)
        signal.signal(signal.SIGTERM, self.__handle_posix_signal)

    def __handle_posix_signal(self, signum, frame):
        if signum == signal.SIGTERM:
            self.__exit()
        if signum == signal.SIGUSR1:
            self.__config_reload()

    async def create_listener(self, local_addr):
        logger.info('local_addr {}'.format(local_addr))
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: self.handler(self.protocol),
            local_addr=local_addr)
        return transport

    def create_connection(self, remote_addr):
        return Connection(
            transport=self.listener,
            remote_addr=remote_addr)

    async def ping(self):
        logger.info('')
        while not self.listener.is_closing():
            self.__ping_connections()
            await asyncio.sleep(1)

    def __ping_connections(self):
        package_protocol = self.protocol['packages']['swarm_ping']
        for connection in self.net_pool.get_all_connections():
            if connection.last_sent_message_is_over_ping_time():
                logger.debug('send ping to {}'.format(connection))
                self.handler(
                    connection=connection,
                    protocol=self.protocol
                ).swarm_ping(
                    package_protocol=package_protocol)

    def __shutdown_connections(self):
        self.net_pool.shutdown()

    def __config_reload(self):
        logger.debug('')
        utilit.import_config()

    def __exit(self):
        logger.info('')
        self.listener.shutdown()
        self.__shutdown_connections()

    def __del__(self):
        logger.debug('')
