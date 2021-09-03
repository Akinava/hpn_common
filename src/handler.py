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
        logger.debug('raw datagram |{}| from {}'.format(request.hex(), remote_addr))
        self.run_stream(
            target=self.__handle,
            request=request,
            remote_addr=remote_addr)

    def connection_lost(self, remote_addr):
        logger.debug('')

    def __handle(self, remote_addr, request):
        connection = Connection(
            transport=self.transport,
            remote_addr=remote_addr,
            request=request)

        if self.crypt_tools.unpack_datagram(connection) is False:
            return
        logger.debug('decrypted datagram {} from {}'.format(connection.get_request().hex(), remote_addr))
        parser = self.parser()
        parser.set_connection(connection)

        if self.__define_package_protocol(parser) is False:
            return
        response_function = self.__get_response_function(parser)
        if response_function is None:
            return

        unpack_request = parser.unpack_package()
        connection.set_unpack_request(unpack_request)
        response_function(connection)

    def __define_package_protocol(self, parser):
        for package_protocol in self.protocol['packages'].values():
            parser.set_package_protocol(package_protocol)
            # logger.debug('check package_protocol {}'.format(package_protocol['name']))
            if self.__define_request(parser):
                logger.debug('package define as {}'.format(package_protocol['name']))
                return True
        logger.warn('GeneralProtocol can not define request')
        return False

    def __define_request(self, parser):
        name_protocol_definition_functions = parser.get_name_protocol_definition_functions()
        for name_protocol_definition_function in name_protocol_definition_functions:
            if not hasattr(self, name_protocol_definition_function):
                logger.debug('define_func {} is not implemented'.format(name_protocol_definition_function))
                return False
            define_func = getattr(self, name_protocol_definition_function)

            # logger.debug('define_func_name {}, result - {}'.format(
            #         name_protocol_definition_function,
            #         define_func(parser)))

            if define_func(parser) is False:
                return False
        return True

    def __get_response_function(self, parser):
        response_function_name = parser.response_function_name()
        if response_function_name is None:
            logger.debug('GeneralProtocol no response_function_name')
            return
        logger.debug('GeneralProtocol response_function_name {}'.format(response_function_name))
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

        parser = self.parser()
        parser.set_connection(receiving_connection)
        parser.set_package_protocol(package_protocol)
        parser.debug_unpack_package(message)

        logger.debug('decrypted_message {} |{}| to {}'.format(
            package_protocol_name,
            message.hex(),
            receiving_connection))


        encrypted_message = self.crypt_tools.encrypt_message(
            message=message,
            package_protocol=package_protocol,
            receiving_connection=receiving_connection)

        logger.debug('encrypted_message {} |{}| to {}'.format(
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

    def verify_hpn_ping(self, parser):
        value = parser.get_part('hpn_ping')
        max = (int(time.time()) + settings.peer_ping_time_seconds) & 0xff
        min = (int(time.time()) - settings.peer_ping_time_seconds) & 0xff
        return check_border_with_over_flow(min, max, value)

    def verify_package_length(self, parser):
        request_length = parser.get_request_length()
        required_length = parser.calc_structure_length()
        return required_length == request_length

    def verify_hpn_protocol_version(self, parser):
        request_major_protocol_version_marker = parser.get_part('major_hpn_protocol_version_marker')
        request_minor_protocol_version_marker = parser.get_part('minor_hpn_protocol_version_marker')
        my_major_protocol_version_marker, my_minor_protocol_version_marker = self.protocol['hpn_protocol_version']
        return my_major_protocol_version_marker >= request_major_protocol_version_marker \
               and my_minor_protocol_version_marker >= request_minor_protocol_version_marker

    def verify_package_id_marker(self, parser):
        request_id_marker = parser.get_part('package_id_marker')
        required_id_marker = parser.get_package_id_marker()
        return request_id_marker == required_id_marker

    def verify_timestamp(self, parser):
        timestamp = parser.get_part('timestamp')
        return check_border_timestamp(timestamp)

    def verify_receiver_fingerprint(self, parser):
        my_fingerprint_from_request = parser.get_part('receiver_fingerprint')
        my_fingerprint_reference = self.crypt_tools.get_fingerprint()
        return my_fingerprint_from_request == my_fingerprint_reference

    def get_receiver_fingerprint(self, **kwargs):
        return kwargs['receiving_connection'].get_fingerprint()

    def get_timestamp(self, **kwargs):
        return self.parser().pack_timestamp()

    def get_package_id_marker(self, **kwargs):
        marker = self.parser().find_package_protocol(kwargs['package_protocol_name'])['package_id_marker']
        return self.parser().pack_int(marker, 1)

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

    def _get_marker_major_hpn_protocol_version_marker(self, **kwargs):
        return self.protocol['hpn_protocol_version'][0]

    def _get_marker_minor_hpn_protocol_version_marker(self, **kwargs):
        return self.protocol['hpn_protocol_version'][1]

