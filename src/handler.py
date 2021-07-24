# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


import time
from settings import logger
import settings
from crypt_tools import Tools as CryptTools
from package_parser import Parser
from connection import Connection, NetPool


class Handler:
    def __init__(self, protocol, message=None, on_con_lost=None, connection=None):
        logger.debug('')
        self.net_pool = NetPool()
        self.crypt_tools = CryptTools()
        self.response = message
        self.__on_con_lost = on_con_lost
        self.connection = connection
        self.transport = None
        self.protocol = protocol
        self.parser = Parser(protocol)

    def connection_made(self, transport):
        logger.debug('')
        self.transport = transport

    def datagram_received(self, request, remote_addr):
        logger.info('%s from %s' % (request.hex(), remote_addr))
        self.connection = Connection(
            remote_addr=remote_addr,
            transport=self.transport,
            request=request
        )
        self.parser.set_connection(self.connection)
        self.crypt_tools.unpack_datagram(self.connection)
        self.__handle()

    def connection_lost(self, remote_addr):
        logger.info('')

    def __handle(self):
        logger.debug('')
        # TODO make a tread
        self.__define_package()
        if self.package_protocol is None:
            return
        response_function = self.__get_response_function()
        if response_function is None:
            return
        return response_function()

    def __define_package(self):
        logger.debug('')
        for package_protocol in self.protocol['packages'].values():
            self.package_protocol = package_protocol
            self.parser.set_package_protocol(package_protocol)
            if self.__define_request():
                logger.info('GeneralProtocol package define as {}'.format(package_protocol['name']))
                return
        self.package_protocol = None
        logger.warn('GeneralProtocol can not define request')

    def __define_request(self):
        define_protocol_functions = self.__get_functions_for_define_protocol()
        for define_func_name in define_protocol_functions:
            if not hasattr(self, define_func_name):
                logger.info('define_func {} is not implemented'.format(define_func_name))
                return False
            define_func = getattr(self, define_func_name)
            if not define_func() is True:
                return False
        return True

    def __get_functions_for_define_protocol(self):
        define_protocol_functions = self.package_protocol['define']
        if isinstance(define_protocol_functions, list):
            return define_protocol_functions
        return [define_protocol_functions]

    def __get_response_function(self):
        response_function_name = self.package_protocol.get('response')
        if response_function_name is None:
            logger.info('GeneralProtocol no response_function_name')
            return
        logger.info('GeneralProtocol response_function_name {}'.format(response_function_name))
        return getattr(self, response_function_name)

    def make_message(self, **kwargs):
        message = b''
        package_structure = self.protocol['packages'][kwargs['package_name']]['structure']
        for part_structure in package_structure:
            if part_structure.get('type') == 'markers':
                build_part_message_function = self.get_markers
                kwargs['markers'] = part_structure
            else:
                build_part_message_function = getattr(self, 'get_{}'.format(part_structure['name']))

            logger.debug('build part {}'.format(part_structure['name']))
            message += build_part_message_function(**kwargs)
        return message

    def send(self, **kwargs):
        connection = kwargs.get('connection', self.connection)
        encrypted_message = self.crypt_tools.encrypt_message(**kwargs, connection=connection)
        connection.send(encrypted_message)

    def define_swarm_ping(self):
        timestamp = self.parser.unpack_timestamp(part_data=self.connection.get_request())
        return timestamp - settings.peer_ping_time_seconds < time.time() < timestamp + settings.peer_ping_time_seconds

    def swarm_ping(self, **kwargs):
        self.send(**kwargs, message=self.parser.pack_timestamp())

    def verify_package_length(self):
        request_length = len(self.connection.get_request())
        required_length = self.parser.calc_structure_length()
        return required_length == request_length

    def verify_protocol_version(self):
        request_major_version_marker = self.parser.get_part('major_version_marker')
        request_minor_version_marker = self.parser.get_part('minor_version_marker')
        my_major_version_marker, my_minor_version_marker = self.protocol['client_protocol_version']
        return my_major_version_marker >= request_major_version_marker \
               and my_minor_version_marker >= request_minor_version_marker

    def verify_package_id_marker(self):
        request_id_marker = self.parser.get_part('package_id_marker')
        required_id_marker = self.package_protocol['package_id_marker']
        return request_id_marker == required_id_marker

    def verify_timestamp(self):
        timestamp = self.parser.get_part('timestamp')
        return time() - settings.peer_ping_time_seconds < timestamp < time() + settings.peer_ping_time_seconds

