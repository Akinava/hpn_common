# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


import asyncio
import signal
from settings import logger
from package_parser import Parser
import utilit
import settings


class Host:
    def __init__(self, net_pool, handler, protocol):
        #logger.debug('')
        self.net_pool = net_pool()
        init_protocol = Parser.init_protocol(protocol)
        self.parser = lambda: Parser(protocol=init_protocol)
        self.handler = lambda: handler(parser=self.parser, net_pool=self.net_pool)
        self.__set_posix_handler()

    async def run(self):
        await self.create_default_listener()
        ping_task = asyncio.create_task(self.ping())
        await ping_task

    async def create_default_listener(self):
        self.default_listener = await self.create_listener(
            (settings.local_host,
             settings.default_port))

    def __set_posix_handler(self):
        signal.signal(signal.SIGUSR1, self.__handle_posix_signal)
        signal.signal(signal.SIGTERM, self.__handle_posix_signal)

    def __handle_posix_signal(self, signum, frame):
        if signum == signal.SIGTERM:
            self.__exit()
        if signum == signal.SIGUSR1:
            self.__config_reload()

    async def create_listener(self, local_addr):
        logger.debug('create listener on port {}'.format(local_addr[1]))
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            protocol_factory=self.handler,
            local_addr=local_addr)
        return transport

    def create_connection(self, transport, remote_addr):
        return self.net_pool.create_connection(remote_addr, transport)

    async def ping(self):
        logger.debug('')
        while not self.default_listener.is_closing():
            self.__ping_connections()
            await asyncio.sleep(1)

    def __ping_connections(self):
        for connection in self.net_pool.get_all_connections():
            if connection.last_sent_message_is_over_ping_time():
                self.handler().hpn_ping(connection)

    def __shutdown_connections(self):
        self.net_pool.shutdown()

    def __config_reload(self):
        logger.debug('')
        utilit.import_config()

    def __exit(self):
        logger.debug('')
        self.listener.shutdown()
        self.__shutdown_connections()

    def __del__(self):
        logger.debug('')
