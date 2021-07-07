# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


import asyncio
import signal
import settings
from settings import logger
from connection import NetPool
from package_parser import Parser
import utilit


class Host:
    def __init__(self, handler, protocol):
        logger.debug('')
        self.__handler = handler
        self.__protocol = Parser.recovery_contraction(protocol)
        self.__net_pool = NetPool()
        self.__local_host = settings.local_host
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
        logger.info('create listener on port {}'.format(local_addr[1]))
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: self.__handler(protocol=self.__protocol),
            local_addr=local_addr)
        return transport

    async def ping(self):
        logger.info('')
        while not self.listener.is_closing():
            self.__ping_connections()
            await asyncio.sleep(1)

    def __ping_connections(self):
        package_protocol = self.__protocol['packages']['swarm_ping']
        for connection in self.__net_pool.get_all_connections():
            if connection.last_sent_message_is_over_ping_time():
                logger.debug('send ping to {}'.format(connection))
                self.__handler(
                    connection=connection,
                    protocol=self.__protocol
                ).swarm_ping(
                    package_protocol=package_protocol)

    def __shutdown_connections(self):
        self.__net_pool.shutdown()

    def __config_reload(self):
        logger.debug('')
        utilit.import_config()

    def __exit(self):
        logger.info('')
        self.listener.shutdown()
        self.__shutdown_connections()

    def __del__(self):
        logger.debug('')
