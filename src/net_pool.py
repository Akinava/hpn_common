# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


from settings import logger
from utilit import Singleton
from connection import Connection
from request import Request


class NetPool(Singleton):
    def __init__(self):
        self.connections_list = []

    def datagram_received(self, transport, request, remote_addr):
        connection = self.create_connection(remote_addr, transport)
        request = Request(request, connection)
        return request

    def create_connection(self, remote_addr, transport):
        connection = Connection(remote_addr=remote_addr, transport=transport)
        connection.set_net_pool(self)
        if connection in self.connections_list:
            return self.connections_list[self.connections_list.index(connection)]
        self.connections_list.append(connection)
        return connection

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

    def set_to_connection_pub_key(self, dst_connection, fingerprint):
        for src_connection in self.connections_list:
            if src_connection.get_fingerprint() == fingerprint:
                self.copy_connection_property(src_connection, dst_connection)
                return True
        return False

    def shutdown(self):
        for connection in self.__group:
            connection.shutdown()
        self.__group = []