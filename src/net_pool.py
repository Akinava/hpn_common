# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


from settings import logger
from utilit import Singleton
from connection import Connection
from datagram import Datagram


class NetPool(Singleton):
    def __init__(self):
        self.connections_list = []

    def datagram_received(self, transport, datagram, remote_addr):
        connection = self.create_connection(remote_addr, transport)
        self.add_connection(connection)
        request = Datagram(
            connection=connection,
            raw_message=datagram)
        return request

    def create_connection(self, remote_addr, transport):
        connection = Connection(remote_addr=remote_addr, transport=transport)
        if connection in self.connections_list:
            return self.connections_list[self.connections_list.index(connection)]
        return connection

    def add_connection(self, connection):
        if not connection in self.connections_list:
            self.connections_list.append(connection)

    def clean_connections_list(self):
        alive_connections_list = []
        for connection in self.connections_list:
            if connection.last_received_message_is_over_time_out():
                logger.debug('host {} disconnected by timeout'.format(connection))
                continue
            alive_connections_list.append(connection)
        self.connections_list = alive_connections_list

    def get_all_connections(self):
        self.clean_connections_list()
        return self.connections_list

    def disconnect(self, connection):
        if connection in self.connections_list:
            logger.debug('disconnect from {}'.format(connection))
            self.connections_list.remove(connection)

    def shutdown(self):
        self.connections_list = []
