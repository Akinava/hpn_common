# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


import struct
import time
from utilit import NULL
from settings import logger


class Parser:
    struct_length = {
        1: 'B',
        2: 'H',
        4: 'I',
        8: 'Q',
    }
    struct_addr = '>BBBBH'

    def __init__(self, protocol):
        self.__protocol = protocol

    def set_package_protocol(self, package_protocol):
        if package_protocol is not None:
            self.package_protocol = package_protocol

    def set_connection(self, connection):
        if connection is not None:
            self.connection = connection

    def find_package_structure(self, **kwargs):
        if 'package_structure' in kwargs:
            return kwargs['package_structure']
        if 'package_protocol_name' in kwargs:
            return self.find_package_protocol(kwargs['package_protocol_name'])['structure']
        raise Exception('Error: no required variables in kwargs {}'.format(kwargs))

    def find_package_protocol(self, package_protocol_name):
        package_protocol = self.__protocol['packages'].get(package_protocol_name)
        if package_protocol is None:
            raise Exception('Error: no protocol with the name {}'.format(package_protocol_name))
        return package_protocol

    def debug_unpack_package(self, message, package_protocol, connection):
        connection.set_request(message)
        self.set_package_protocol(package_protocol)
        self.set_connection(connection)
        unpack_request = {}
        for part_structure in self.package_protocol['structure']:
            part_data, data = self.__unpack_stream(message, part_structure['length'])
            part_package = self.unpack_type(part_data, part_structure)
            unpack_request.update(part_package)

        for k, v in unpack_request.items():
            if isinstance(v, bytes):
                unpack_request[k] = v.hex()

        logger.debug('package {} send to {} package_structure {}'.format(
            self.package_protocol['name'],
            connection,
            unpack_request))

    def unpack_package(self, package_protocol, connection):
        self.set_package_protocol(package_protocol)
        self.set_connection(connection)
        data = self.connection.get_request()
        unpack_request = {}
        for part_structure in self.package_protocol['structure']:
            if part_structure.get('type', NULL()) == 'list':
                list_length, data = self.unpack_self_defined_int(data)
                list_structure_size = self.calc_list_structure_size(part_structure['name'])
                length = list_length * list_structure_size
            else:
                length = part_structure['length']
            part_data, data = self.__unpack_stream(data, length)
            part_package = self.unpack_type(part_data, part_structure)
            unpack_request.update(part_package)
        return unpack_request

    def unpack_type(self, part_data, part_structure):
        part_type = part_structure.get('type', NULL())
        part_name = part_structure['name']
        if part_type is NULL():
            return {part_name: part_data}
        unpack_type_function = getattr(self, 'unpack_{}'.format(part_type))
        unpack_data = unpack_type_function(part_name=part_name, part_data=part_data)
        if isinstance(unpack_data, dict):
            return unpack_data
        return {part_name: unpack_data}

    def unpack_list(self, **kwargs):
        structure = self.__protocol['lists'][kwargs['part_name']]['structure']
        data = kwargs['part_data']
        unpack_data_list = []
        while data:
            unpack_data_item = {}
            for part_structure in structure:
                length = part_structure['length']
                part_data, data = self.__unpack_stream(data, length)
                part_package = self.unpack_type(part_data, part_structure)
                unpack_data_item.update(part_package)
            unpack_data_list.append(unpack_data_item)
        return {kwargs['part_name']: unpack_data_list}

    def unpack_hpn_servers_protocol(self, **kwargs):
        int_data, _ = self.unpack_self_defined_int(kwargs['part_data'])
        unpack_data = self.unpack_mapping('hpn_servers_protocol', int_data)
        return {kwargs['part_name']: unpack_data}

    def unpack_hpn_ping(self, part_name, part_data):
        return {'ping': part_data}

    def unpack_mapping(self, mapping_name, mapping_data):
        structure = self.__protocol['mapping'][mapping_name]['structure']
        inv_structure = {v: k for k, v in structure.items()}
        return inv_structure[mapping_data]

    def unpack_timestamp(self, **kwargs):
        return self.unpack_int(**kwargs)

    def unpack_bool_marker(self, **kwargs):
        return kwargs['part_data'] == 1

    def pack_bool(self, part_data):
        return b'\x01' if part_data else b'\x00'

    def unpack_bool(self, **kwargs):
        return kwargs['part_data'] == b'\x01'

    def pack_addr(self, addr):
        host, port = addr
        return struct.pack(self.struct_addr, *(map(int, host.split('.'))), port)

    def unpack_addr(self, **kwargs):
        res = struct.unpack(self.struct_addr, kwargs['part_data'])
        host = '.'.join(map(str, res[:4]))
        port = res[4]
        return (host, port)

    def get_part(self, name, package_protocol):
        self.set_package_protocol(package_protocol)
        return self.unpack_package().get(name, NULL())

    def calc_structure_length(self, package_structure, connection=None):
        self.set_connection(connection)
        length = 0
        for part in package_structure:
            if length > len(self.connection.get_request()):
                return None
            if part.get('type') == 'list':
                length += self.calc_list_length(
                    list_name=part['name'],
                    skip_bytes=length)
                continue
            length += part['length']
        return length

    def calc_list_length(self, list_name, skip_bytes):
        data = self.connection.get_request()[skip_bytes:]
        size, rest = self.unpack_self_defined_int(data)
        size_bytes = len(data) - len(rest)
        list_structure_length = self.calc_list_structure_size(list_name)
        return size * list_structure_length + size_bytes

    def calc_list_structure_size(self, list_name):
        list_structure = self.__protocol['lists'][list_name]['structure']
        return self.calc_structure_length(package_structure=list_structure)

    @classmethod
    def get_packed_addr_length(cls):
        return struct.calcsize(cls.struct_addr)

    @classmethod
    def init_protocol(cls, protocol):
        protocol = cls.convert_protocol_to_dict(protocol)
        protocol = cls.recovery_protocol_contraction(protocol)
        return protocol

    @classmethod
    def convert_protocol_to_dict(cls, protocol):
        for key in ['packages', 'markers', 'lists', 'contraction', 'mapping']:
            items_list = protocol[key]
            items_dict = {}
            for item in items_list:
                items_dict[item['name']] = item
            protocol[key] = items_dict
        return protocol

    @classmethod
    def recovery_protocol_contraction(cls, protocol):
        def get_define_name_list(package_protocol):
            if isinstance(package_protocol['define'], list):
                return package_protocol['define']
            return [package_protocol['define']]

        def get_structures_name_list(package_protocol):
            structure = package_protocol.get('structure')
            return [part['name'] for part in structure]

        def recovery_contraction_name(place, contraction_items, items):
            if isinstance(items, list):
                return items[: place] + contraction_items['structure'] + items[place+1: ]
            else:
                return contraction_items['structure']

        def recovery_define(package_protocol, found_define_contraction):
            for contraction_name in found_define_contraction:
                place = package_protocol['define'].index(contraction_name)
                contraction = protocol['contraction'][contraction_name]
                package_define = package_protocol['define']
                package_protocol['define'] = recovery_contraction_name(place, contraction, package_define)

        def recovery_structure(package_protocol, found_structure_contraction):
            structures_name_list = get_structures_name_list(package_protocol)
            for contraction_name in found_structure_contraction:
                place = structures_name_list.index(contraction_name)
                contraction = protocol['contraction'][contraction_name]
                package_structure = package_protocol['structure']
                package_protocol['structure'] = recovery_contraction_name(place, contraction, package_structure)

        contractions_name = protocol['contraction'].keys()

        for package_protocol in protocol['packages'].values():
            define_name_list = get_define_name_list(package_protocol)
            found_define_contraction = set(contractions_name) & set(define_name_list)
            if found_define_contraction:
                recovery_define(package_protocol, found_define_contraction)

            structures_name_list = get_structures_name_list(package_protocol)
            found_structure_contraction = set(contractions_name) & set(structures_name_list)
            if structures_name_list:
                recovery_structure(package_protocol, found_structure_contraction)

        return protocol

    def pack_timestamp(self):
        return self.pack_int(int(time.time()), 4)

    def unpack_markers(self, **kwargs):
        if not isinstance(kwargs['part_name'], tuple):
            return self.unpack_single_marker(kwargs['part_name'], kwargs['part_data'])
        return self.unpack_multiple_marker(kwargs['part_name'], kwargs['part_data'])

    def unpack_multiple_marker(self, part_name_list, markers_data):
        unpack_package = {}
        for marker_name in part_name_list:
            marker_data_int = self.__split_markers(marker_name, markers_data)
            unpack_package[marker_name] = self.set_marker_type(marker_name, marker_data_int)
        return unpack_package

    def unpack_single_marker(self, marker_name, marker_data):
        marker_data = self.unpack_int(part_data=marker_data)
        marker_data_int = self.unpack_int(part_data=marker_data)
        return {marker_name: self.set_marker_type(marker_name, marker_data_int)}

    def set_marker_type(self, marker_name, marker_data):
        marker_structure = self.__get_marker_description(marker_name)
        marker_type = marker_structure.get('type', NULL())
        if marker_type is NULL():
            return marker_data
        set_type_function = getattr(self, 'unpack_{}'.format(marker_type))
        return set_type_function(part_data=marker_data)

    def unpack_int_marker(self, **kwargs):
        return kwargs['part_data']

    def unpack_bool_marker(self, **kwargs):
        return kwargs['part_data'] == 1

    def __split_markers(self, marker_name, markers_data):

        request = self.connection.get_request().hex() if hasattr(self, 'connection') else None
        logger.info('marker_name {}, markers_data {}, request {}'.format(marker_name, markers_data.hex(), request))

        marker_structure = self.__get_marker_description(marker_name)
        markers_data_length = len(markers_data)
        marker_mask = self.__make_mask(
            marker_structure['start_bit'],
            marker_structure['length'],
            markers_data_length)
        left_shift = self.__get_left_shift(
            marker_structure['start_bit'],
            marker_structure['length'],
            markers_data_length)
        marker_packed_int = self.unpack_int(part_data=markers_data)
        marker_data = marker_packed_int & marker_mask
        return marker_data >> left_shift

    def __make_mask(self, start_bit, length_bit, length_data_byte):
        return ((1 << length_bit) - 1) << 8 * length_data_byte - start_bit - length_bit

    def __get_left_shift(self, start_bit, length_bit, length_data_byte):
        return length_data_byte * 8 - start_bit - length_bit

    def __get_marker_description(self, marker_name):
        for marker_description in self.__protocol.get('markers', {}).values():
            if marker_description['name'] == marker_name:
                return marker_description
        raise Exception('Error: no description for marker {}'.format(marker_name))

    def pack_mapping(self, mapping_name, mapping_data):
        structure = self.__protocol['mapping'][mapping_name]['structure']
        return self.pack_self_defined_int(structure[mapping_data])

    def unpack_int(self, **kwargs):
        return struct.unpack('>' + self.struct_length[len(kwargs['part_data'])], kwargs['part_data'])[0]

    def pack_int(self, data, size):
        return struct.pack('>' + self.struct_length[size], data)

    def __unpack_stream(self, data, length):
        return data[: length], data[length:]

    def unpack_self_defined_int(self, data):
        number = data[0]  # binary convert to int by magic ¯\_(ツ)_/¯
        data = data[1:]
        if number <= 0xfc:
            return number, data
        if number == 0xfd:
            return self.unpack_int(part_data=data[:2]), data[2:]
        if number == 0xfe:
            return self.unpack_int(part_data=data[:4]), data[4:]
        if number == 0xff:
            return self.unpack_int(part_data=data[:8]), data[8:]

    def pack_self_defined_int(self, number):
        if number <= 0xfc:
            return self.pack_int(data=number, size=1)
        if number <= (1 << (8*2))-1:
            return self.pack_int(data=0xfd, size=1) + self.pack_int(data=number, size=2)
        if number <= (1 << (8*4))-1:
            return self.pack_int(data=0xfe, size=1) + self.pack_int(data=number, size=4)
        if number <= (1 << (8*8))-1:
            return self.pack_int(data=0xff, size=1) + self.pack_int(data=number, size=8)


