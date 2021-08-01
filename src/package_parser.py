# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


import struct
import time
from utilit import NULL


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
        if package_protocol is None:
            return
        self.package_protocol = package_protocol

    def find_protocol_package(self, package_name):
        protocol_package = self.__protocol['packages'].get(package_name)
        if protocol_package is None:
            raise Exception('Error: no protocol with the name {}'.format(package_name))
        return protocol_package

    def set_connection(self, connection):
        self.connection = connection

    def unpack_package(self):
        package = {}
        data = self.connection.get_request()
        package_structure = self.package_protocol['structure']
        for part_structure in package_structure:
            part_data, data = self.__unpack_stream(data, part_structure['length'])
            part_package = self.unpack_type(part_data, part_structure)
            package.update(part_package)
        return package

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

    def set_type(self, part_data, part_structure):
        part_name = part_structure['name']
        part_type = part_structure.get('type', NULL())
        if part_type is NULL():
            return {part_name: part_data}

        set_type_function = getattr(self, 'unpack_{}'.format(part_type))
        package_data = set_type_function(part_name=part_name, part_data=part_data)

        if isinstance(package_data, dict):
            return package_data
        return {part_name: package_data}

    def unpack_timestamp(self, **kwargs):
        return self.unpack_int(kwargs['part_data'])

    def unpack_bool_marker(self, **kwargs):
        return kwargs['part_data'] == 1

    def pack_bool(self, part_data):
        return b'\x01' if part_data else b'\x00'

    def unpack_bool(self, **kwargs):
        return kwargs['part_data'] == b'\x01'

    def get_part(self, name, package_protocol=None):
        self.set_package_protocol(package_protocol)
        return self.unpack_package().get(name, NULL())

    def calc_structure_length(self, structure=None):
        if structure is None:
            structure = self.package_protocol['structure']
        length = 0
        for part in structure:
            if part.get('type') == 'list':
                length += self.calc_list_length(part['name'], length)
                continue
            length += part['length']
        return length

    def calc_list_length(self, list_name, skip_bytes):
        data = self.connection.get_request()[skip_bytes:]
        size, _ = self.unpack_size(data)
        list_structure = self.__protocol['lists'][list_name]['structure']
        list_structure_length = self.calc_structure_length(structure=list_structure)
        return size * list_structure_length

    def pack_addr(self, addr):
        host, port = addr
        return struct.pack(self.struct_addr, *(map(int, host.split('.'))), port)

    @classmethod
    def get_packed_addr_length(cls):
        return struct.calcsize(cls.struct_addr)

    @classmethod
    def recovery_contraction(cls, protocol):
        def get_define_name_list(package_protocol):
            if isinstance(package_protocol['define'], list):
                return package_protocol['define']
            return [package_protocol['define']]

        def get_structure_name_list(package_protocol):
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
            structure_name_list = get_structure_name_list(package_protocol)
            for contraction_name in found_structure_contraction:
                place = structure_name_list.index(contraction_name)
                contraction = protocol['contraction'][contraction_name]
                package_structure = package_protocol['structure']
                package_protocol['structure'] = recovery_contraction_name(place, contraction, package_structure)

        contractions_name = protocol['contraction'].keys()

        for package_protocol in protocol['packages'].values():
            define_name_list = get_define_name_list(package_protocol)
            found_define_contraction = set(contractions_name) & set(define_name_list)
            if found_define_contraction:
                recovery_define(package_protocol, found_define_contraction)

            structure_name_list = get_structure_name_list(package_protocol)
            found_structure_contraction = set(contractions_name) & set(structure_name_list)
            if structure_name_list:
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
            marker_structure = self.__get_marker_description(marker_name)
            marker_data = self.__split_markers(marker_structure, markers_data)
            unpack_package[marker_name] = marker_data
        return unpack_package

    def unpack_single_marker(self, marker_name, marker_data):
        return {marker_name: self.unpack_int(marker_data)}

    def __split_markers(self, marker_structure, markers_data):
        markers_data_length = len(markers_data)
        marker_mask = self.__make_mask(
            marker_structure['start_bit'],
            marker_structure['length'],
            markers_data_length)
        left_shift = self.__get_left_shift(
            marker_structure['start_bit'],
            marker_structure['length'],
            markers_data_length)
        marker_packed_int = self.unpack_int(markers_data)
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

    def unpack_int(self, data):
        return struct.unpack('>' + self.struct_length[len(data)], data)[0]

    def pack_int(self, data, size):
        return struct.pack('>' + self.struct_length[size], data)

    def __unpack_stream(self, data, length):
        return data[: length], data[length:]

    def unpack_size(self, data):
        size = data[0]  # binary convert to int by magic ¯\_(ツ)_/¯
        data = data[1:]
        if size <= 0xfc:
            return size, data
        if size == 0xfd:
            return self.unpack_int(data[:2]), data[2:]
        if size == 0xfe:
            return self.unpack_int(data[:4]), data[4:]
        if size == 0xff:
            return self.unpack_int(data[:8]), data[8:]
