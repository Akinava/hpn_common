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

    @classmethod
    def get_packed_addr_length(cls):
        return struct.calcsize(cls.struct_addr)

    @classmethod
    def recovery_contraction(cls, protocol):
        def get_define_name_list(package_protocol):
            return package_protocol['define']

        def get_structure_name_list(package_protocol):
            structure = package_protocol.get('structure')
            return [part['name'] for part in structure]

        def recovery_contraction_name(place, contraction_items, items):
            return items[: place] + contraction_items['structure'] + items[place+1: ]

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

    def set_package_protocol(self, package_protocol):
        self.package_protocol = package_protocol

    def set_connection(self, connection):
        self.connection = connection

    def unpack_package(self):
        package = {}
        data = self.connection.get_request()
        package_structure = self.package_protocol['structure']
        for part_structure in package_structure:
            part_name = part_structure['name']
            part_data, data = self.__unpack_stream(data, part_structure['length'])
            part_data = self.unpack_type(part_data, part_structure)
            package[part_name] = part_data
            self.__unpack_markers(part_name, package)
        return package

    def unpack_type(self, part_data, part_structure):
        part_type = part_structure.get('type', NULL())
        if part_type is NULL():
            return part_data
        unpack_type_function = getattr(self, 'unpack_{}'.format(part_type))
        return unpack_type_function(part_data)

    def unpack_timestamp(self, part_data):
        return self.unpack_int(part_data)

    def unpack_bool_marker(self, part_data):
        return part_data == 1

    def pack_bool(self, part_data):
        return b'\x01' if part_data else b'\x00'

    def get_part(self, name):
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
    def get_packed_addr_length(self):
        return struct.calcsize(self.struct_addr)

    def pack_timestamp(self):
        return self.pack_int(int(time.time()), 4)

    def unpack_markers(self, **kwargs):
        if not isinstance(kwargs['part_name'], tuple):
            return self.unpack_single_marker(kwargs['part_name'], kwargs['part_data'])
        return self.unpack_multiple_marker(kwargs['part_name'], kwargs['part_data'])

    def __unpack_markers(self, part_name, package):
        if not isinstance(part_name, tuple):
            return
        for marker_name in part_name:
            marker_structure = self.__get_marker_description(marker_name)
            marker_data = self.__unpack_marker(marker_structure, markers_packed_data)
            package[marker_name] = marker_data
        del package[markers]

    def __unpack_marker(self, marker_structure, marker_packed_data):
        marker_packed_data_length = len(markers_packed_data)
        marker_mask = self.__make_mask(marker_structure['start bit'], marker_structure['length'], marker_packed_data_length)
        left_shift = self.__get_left_shift(marker_structure['start bit'], marker_structure['length'], marker_packed_data_length)
        marker_packed_int = self.unpack_int(marker_packed_data)
        marker_data = marker_packed_int & marker_mask
        return marker_data >> left_shift

    def __make_mask(self, start_bit, length_bit, length_data_byte):
        return ((1 << length_bit) - 1) << 8 * length_data_byte - start_bit - length_bit

    def __get_left_shift(self, start_bit, length_bit, length_data_byte):
        return length_data_byte * 8 - start_bit - length_bit

    def __get_marker_description(self, marker_name):
        for marker_description in self.__protocol.get('markers', []):
            if marker_description['name'] == marker_name:
                return marker_description
        raise Exception('Error: no description for marker {}'.format(marker_name))

    def unpack_int(self, data):
        return struct.unpack('>' + self.struct_length[len(data)], data)[0]

    def pack_int(self, data, size):
        return struct.pack('>' + self.struct_length[size], data)

    def __unpack_stream(self, data, length):
        return data[ :length], data[length: ]

    def unpack_size(self, data):
        size = self.unpack_int(data[0])
        data = data[1:]
        if size <= 0xfc:
            return size, data
        if size == 0xfd:
            return self.unpack_int(data[:2]), data[2:]
        if size == 0xfe:
            return self.unpack_int(data[:4]), data[4:]
        if size == 0xff:
            return self.unpack_int(data[:8]), data[8:]
