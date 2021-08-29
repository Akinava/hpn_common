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
from utilit import check_border_with_over_flow, check_border_timestamp, Stream


class Handler(Stream):
    def __init__(self, protocol, on_con_lost=None):
        #logger.debug('')
        self.net_pool = NetPool()
        self.crypt_tools = CryptTools()
        self.__on_con_lost = on_con_lost
        self.transport = None
        self.protocol = protocol
        self.parser = lambda: Parser(protocol=protocol)

    def connection_made(self, transport):
        #logger.debug('')
        self.transport = transport

    def datagram_received(self, request, remote_addr):
        logger.info('handler {} got raw datagram |{}| from {}'.format(self, request.hex(), remote_addr))
        self.run_stream(
            target=self.__handle,
            request=request,
            remote_addr=remote_addr)

    def connection_lost(self, remote_addr):
        logger.info('')

    def __handle(self, remote_addr, request):
        connection = Connection(
            transport=self.transport,
            remote_addr=remote_addr,
            request=request)

        if self.crypt_tools.unpack_datagram(connection) is False:
            return
        logger.info('decrypted datagram {} from {}'.format(connection.get_request().hex(), remote_addr))
        package_protocol = self.__define_package_protocol(connection)
        if package_protocol is None:
            return
        response_function = self.__get_response_function(package_protocol)
        if response_function is None:
            return

        unpack_request = self.parser().unpack_package(
            package_protocol=package_protocol,
            connection=connection)
        connection.set_unpack_request(unpack_request)
        response_function(connection)

    def __define_package_protocol(self, connection):
        for package_protocol in self.protocol['packages'].values():
            logger.info('check package_protocol {}'.format(package_protocol['name']))
            if self.__define_request(connection, package_protocol):
                logger.info('package define as {}'.format(package_protocol['name']))
                return package_protocol
        logger.warn('GeneralProtocol can not define request')

    def __define_request(self, connection, package_protocol):
        define_protocol_functions = self.__get_functions_for_define_protocol(package_protocol)
        for define_func_name in define_protocol_functions:
            if not hasattr(self, define_func_name):
                logger.info('define_func {} is not implemented'.format(define_func_name))
                return False
            define_func = getattr(self, define_func_name)

            logger.debug(
                'protocol {}, define_func_name {}, result - {}'.format(
                    package_protocol['name'],
                    define_func_name,
                    define_func(connection, package_protocol)))

            if define_func(connection, package_protocol) is False:
                return False
        return True

    def __get_functions_for_define_protocol(self, package_protocol):
        define_protocol_functions = package_protocol['define']
        if isinstance(define_protocol_functions, list):
            return define_protocol_functions
        return [define_protocol_functions]

    def __get_response_function(self, package_protocol):
        response_function_name = package_protocol.get('response')
        if response_function_name is None:
            logger.info('GeneralProtocol no response_function_name')
            return
        logger.info('GeneralProtocol response_function_name {}'.format(response_function_name))
        return getattr(self, response_function_name)

    def make_message(self, **kwargs):
        package_structure = self.parser().find_package_structure(**kwargs)
        message = b''
        for part_structure in package_structure:
            if part_structure.get('type') == 'markers':
                make_part_message_function = self.get_markers
                kwargs['markers_structure'] = part_structure
            else:
                make_part_message_function = getattr(self, 'get_{}'.format(part_structure['name']))

            logger.debug('make part {} {}'.format(
                part_structure['name'],
                make_part_message_function(**kwargs).hex()))

            message += make_part_message_function(**kwargs)
        return message

    def send(self, **kwargs):
        # reason some of the message can be too long and time consuming
        self.run_stream(
            target=self.thread_send,
            **kwargs
        )

    def thread_send(self, message, package_protocol_name, receiving_connection):
        package_protocol = self.protocol['packages'][package_protocol_name]

        self.parser().debug_unpack_package(
            message=message,
            package_protocol=package_protocol,
            connection=receiving_connection)

        logger.info('decrypted_message {} |{}| to {}'.format(
            package_protocol_name,
            message.hex(),
            receiving_connection))


        encrypted_message = self.crypt_tools.encrypt_message(
            message=message,
            package_protocol=package_protocol,
            receiving_connection=receiving_connection)

        logger.info('encrypted_message {} |{}| to {}'.format(
            package_protocol_name,
            encrypted_message.hex(),
            receiving_connection))

        receiving_connection.send(encrypted_message)

    def hpn_ping(self, receiving_connection):
        message = self.parser().pack_int(int(time.time()) & 0xff, 1)
        self.send(
            package_protocol_name='hpn_ping',
            receiving_connection=receiving_connection,
            message=message
        )

    def verify_hpn_ping(self, connection, package_protocol):
        value = self.parser().unpack_int(part_data=connection.get_request())
        max = (int(time.time()) + settings.peer_ping_time_seconds) & 0xff
        min = (int(time.time()) - settings.peer_ping_time_seconds) & 0xff
        return check_border_with_over_flow(min, max, value)

    def verify_package_length(self, connection, package_protocol):
        request_length = len(connection.get_request())
        required_length = self.parser().calc_structure_length(
            package_structure=package_protocol['structure'],
            connection=connection)
        logger.info('request_length {}, required_length {}, request {}'.format(request_length, required_length, connection.get_request().hex()))
        return required_length == request_length

    def verify_protocol_version(self, connection, package_protocol):
        logger.info(self.connection.get_request().hex())
        request_major_protocol_version_marker = self.parser.get_part('major_protocol_version_marker')
        request_minor_protocol_version_marker = self.parser.get_part('minor_protocol_version_marker')
        my_major_protocol_version_marker, my_minor_protocol_version_marker = self.protocol['client_protocol_version']
        return my_major_protocol_version_marker >= request_major_protocol_version_marker \
               and my_minor_protocol_version_marker >= request_minor_protocol_version_marker

    def verify_package_id_marker(self, connection, package_protocol):
        request_id_marker = self.parser.get_part('package_id_marker')
        required_id_marker = self.package_protocol['package_id_marker']
        return request_id_marker == required_id_marker

    def verify_timestamp(self, connection, package_protocol):
        timestamp = self.parser.get_part('timestamp')
        return check_border_timestamp(timestamp)

    def verify_receiver_fingerprint(self, connection, package_protocol):
        my_fingerprint_from_request = self.parser().get_part('receiver_fingerprint')
        my_fingerprint_reference = self.crypt_tools.get_fingerprint()
        return my_fingerprint_from_request == my_fingerprint_reference

    def get_receiver_fingerprint(self, **kwargs):
        return kwargs['receiving_connection'].get_fingerprint()

    def get_timestamp(self, **kwargs):
        return self.parser().pack_timestamp()

    def get_package_id_marker(self, **kwargs):
        marker = self.parser().find_package_protocol(kwargs['package_protocol_name'])['package_id_marker']
        return self.parser.pack_int(marker, 1)

    def get_markers(self, **kwargs):
        markers = 0
        for marker_name in kwargs['markers_structure']['name']:
            get_marker_value_function = getattr(self, '_get_marker_{}'.format(marker_name))
            marker = get_marker_value_function(**kwargs)
            marker_description = self.protocol['markers'][marker_name]
            markers ^= self.make_marker(marker, marker_description, kwargs['markers_structure'])
        packed_markers = self.parser().pack_int(markers, kwargs['markers_structure']['length'])
        del kwargs['markers_structure']
        return packed_markers

    def make_marker(self, marker, marker_description, part_structure):
        part_structure_length_bits = part_structure['length'] * 8
        left_shift = part_structure_length_bits - marker_description['start_bit'] - marker_description['length']
        return marker << left_shift

    def _get_marker_major_client_protocol_version_marker(self, **kwargs):
        return self.protocol['client_protocol_version'][0]

    def _get_marker_minor_client_protocol_version_marker(self, **kwargs):
        return self.protocol['client_protocol_version'][1]

