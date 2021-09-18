# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


import time
from settings import logger
import settings
from datagram import Datagram
from crypt_tools import Tools as CryptTools
from utilit import check_border_with_over_flow, check_border_timestamp, Stream, null, JObj


class Handler(Stream):
    def __init__(self, net_pool, parser, on_con_lost=None):
        self.net_pool = net_pool
        self.crypt_tools = CryptTools()
        self.__on_con_lost = on_con_lost
        self.transport = None
        self.parser = parser

    def connection_made(self, transport):
        #logger.debug('')
        self.transport = transport

    def datagram_received(self, datagram, remote_addr):
        logger.debug('=' * 20)
        logger.debug('raw datagram |{}| from {}'.format(datagram.hex(), remote_addr))
        request = self.net_pool.datagram_received(self.transport, datagram, remote_addr)
        self.run_stream(
            target=self.__handle,
            request=request)

    def connection_lost(self, remote_addr):
        logger.debug('')

    def unpack_datagram(self, request):
        if self.crypt_tools.is_encrypted(request) is False:
            request.set_decrypted_message(request.raw_message)
            return True

        pub_key = request.connection.get_pub_key()
        if pub_key:
            return self.crypt_tools.decrypt_request(pub_key, request)

        if hasattr(self, 'extended_get_pub_key') is False:
            logger.warn('can\'t unpack datagram from {}'.format(request))
            return False

        pub_key = self.extended_get_pub_key(request)
        if pub_key:
            return self.crypt_tools.decrypt_request(pub_key, request)
        logger.warn('can\'t unpack datagram from {}'.format(request))
        return False

    def __handle(self, request):
        if self.unpack_datagram(request) if False:
            logger.warn('can\'t unpack datagram from {}'.format(request))
            return

        #logger.debug('decrypted datagram {} from {}'.format(connection.get_request().hex(), remote_addr))
        parser = self.parser()
        parser.set_message(request.decrypted_message)

        if self.__define_package_protocol(parser) is False:
            return

        request.set_unpack_message(parser.unpack_package)
        request.set_package_protocol(parser.package_protocol)

        parser.debug_unpack_package(request.decrypted_message)

        response_function = self.__get_response_function(request)
        if response_function is None:
            logger.debug('GeneralProtocol no response_function_name')
            logger.debug('=' * 20)
            return
        logger.debug('GeneralProtocol response_function_name {}'.format(request.package_protocol.response))
        logger.debug('=' * 20)
        response_function(request)

    def __define_package_protocol(self, parser):
        for package_protocol in parser.protocol.packages.values():
            parser.set_package_protocol(package_protocol)
            # logger.debug('check package_protocol {}'.format(package_protocol['name']))
            if self.__define_request(parser):
                logger.debug('package define as {}'.format(package_protocol['name']))
                return True
        logger.warn('GeneralProtocol can not define request')
        return False

    def __define_request(self, parser):
        name_protocol_definition_functions = parser.package_protocol.define
        for name_protocol_definition_function in name_protocol_definition_functions:
            define_func = getattr(self, name_protocol_definition_function)
            logger.debug('protocol name {}, define_func_name {}, result - {}'.format(
                    parser.package_protocol.name,
                    name_protocol_definition_function,
                    define_func(parser)))
            if define_func(parser) is False:
                return False
        return True

    def __get_response_function(self, request):
        response_function_name = request.package_protocol.response
        if response_function_name is null:
            return
        return getattr(self, response_function_name)

    def make_message(self, **kwargs):
        response_package_protocol_name = kwargs['request'].package_protocol.response
        response_package_protocol = self.parser().find_package_protocol(
            package_protocol_name=response_package_protocol_name)
        kwargs['response'].set_package_protocol(response_package_protocol)
        kwargs['structure'] = response_package_protocol.structure
        message = self.make_message_by_structure(**kwargs)
        kwargs['response'].set_decrypted_message(message)

    def make_message_by_structure(self, **kwargs):
        message = b''
        for part_structure in kwargs['structure']:
            if part_structure.type == 'markers':
                make_part_message_function = self.get_markers
                kwargs['markers_structure'] = part_structure
            else:
                make_part_message_function = getattr(self, 'get_{}'.format(part_structure.name))

            # logger.debug('make part {} {}'.format(
            #     part_structure['name'],
            #     make_part_message_function(**kwargs).hex()))

            message += make_part_message_function(**kwargs)
        return message

    def send(self, **kwargs):
        self.run_stream(target=self.thread_send, **kwargs)

    def thread_send(self, **kwargs):
        self.make_message(**kwargs)
        response = kwargs['response']
        self.crypt_tools.encrypt_message(response=response)

        logger.debug('=' * 20)
        logger.debug('message send to {} package {}'.format(response.connection, response.package_protocol.name))
        parser = self.parser()
        parser.set_package_protocol(response.package_protocol)
        parser.debug_unpack_package(response.decrypted_message)
        logger.debug('encrypted_message {} |{}| to {}'.format(
            response.package_protocol.name,
            response.raw_message.hex(),
            response.connection))
        logger.debug('=' * 20)

        response.connection.send(response.raw_message)

    def hpn_ping(self, receiving_connection):
        request = Datagram(connection=receiving_connection)
        response = Datagram(connection=receiving_connection)
        request.set_package_protocol(JObj({'response': 'hpn_ping'}))
        self.send(request=request, response=response)

    def get_hpn_ping(self, **kwargs):
        return self.parser().pack_int(int(time.time()) & 0xff, 1)

    def verify_hpn_ping(self, parser):
        if settings.peer_ping_time_seconds >= 0x80:
            return True
        value = parser.unpack_package.hpn_ping
        max = (int(time.time()) + settings.peer_ping_time_seconds) & 0xff
        min = (int(time.time()) - settings.peer_ping_time_seconds) & 0xff
        return check_border_with_over_flow(min, max, value)

    def verify_package_length(self, parser):
        request_length = parser.get_request_length()
        required_length = parser.calc_structure_length()
        return required_length == request_length

    def verify_hpn_protocol_version(self, parser):
        request_major_protocol_version_marker = parser.unpack_package.major_hpn_protocol_version_marker
        request_minor_protocol_version_marker = parser.unpack_package.minor_hpn_protocol_version_marker
        my_major_protocol_version_marker = parser.protocol.hpn_protocol_version[0]
        my_minor_protocol_version_marker = parser.protocol.hpn_protocol_version[1]
        return my_major_protocol_version_marker >= request_major_protocol_version_marker \
               and my_minor_protocol_version_marker >= request_minor_protocol_version_marker

    def verify_package_id_marker(self, parser):
        request_id_marker = parser.unpack_package.package_id_marker
        required_id_marker = parser.package_protocol.package_id_marker
        return request_id_marker == required_id_marker

    def verify_timestamp(self, parser):
        timestamp = parser.unpack_package.timestamp
        return check_border_timestamp(timestamp)

    def verify_receiver_fingerprint(self, parser):
        my_fingerprint_from_request = parser.unpack_package.receiver_fingerprint
        my_fingerprint_reference = self.crypt_tools.get_fingerprint()
        return my_fingerprint_from_request == my_fingerprint_reference

    def get_receiver_fingerprint(self, **kwargs):
        return kwargs['response'].connection.get_fingerprint()

    def get_timestamp(self, **kwargs):
        return self.parser().pack_timestamp()

    def get_package_id_marker(self, **kwargs):
        marker = kwargs['response'].package_protocol.package_id_marker
        return self.parser().pack_int(marker, 1)

    def get_markers(self, **kwargs):
        markers = 0
        markers_structure = kwargs['markers_structure']
        for marker_name in markers_structure.name:
            get_marker_value_function = getattr(self, '_get_marker_{}'.format(marker_name))
            marker = get_marker_value_function(**kwargs)
            marker_description = self.parser().protocol.markers[marker_name]
            markers ^= self.make_marker(marker, marker_description, markers_structure)
        packed_markers = self.parser().pack_int(markers, markers_structure.length)
        return packed_markers

    def make_marker(self, marker, marker_description, part_structure):
        part_structure_length_bits = part_structure['length'] * 8
        left_shift = part_structure_length_bits - marker_description['start_bit'] - marker_description['length']
        return marker << left_shift

    def _get_marker_major_hpn_protocol_version_marker(self, **kwargs):
        return self.parser().protocol.hpn_protocol_version[0]

    def _get_marker_minor_hpn_protocol_version_marker(self, **kwargs):
        return self.parser().protocol.hpn_protocol_version[1]

