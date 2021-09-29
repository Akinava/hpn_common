# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


import struct
from utilit import debug_obj
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
        self.protocol = protocol

    def set_package_protocol(self, package_protocol):
        self.package_protocol = package_protocol

    def set_message(self, message):
        self.message = message

    def fill_in_request(self, request):
        request.set_unpack_message(self.unpack_package())
        request.set_package_protocol(self.package_protocol)

    def debug_unpack_package(self, datagram, direction):
        self.message = datagram.decrypted_message
        logger.debug('package {} {} {} {}'.format(
            self.package_protocol['name'],
            direction,
            datagram.connection,
            debug_obj(self.unpack_package()),
        ))

    def unpack_package(self, data=None, structure=None):
        def unpack_data_part(data_part, part_structure):
            if 'length' in part_structure:
                return self.__get_data_part(data_part, part_structure['length'])
            else:
                return self.__get_object_data(data_part, part_structure)

        data = data or self.message
        structure = structure or self.package_protocol['structure']
        unpack_request = {}

        for part_structure in structure:
            part_data, data = unpack_data_part(data, part_structure)
            unpack_request.update(self.unpack_type(part_data, part_structure))
        return unpack_request

    def calc_structure_length(self, structure=None):
        structure = structure or self.package_protocol['structure']
        length = 0

        for part_structure in structure:
            if 'length' in part_structure:
                length += part_structure['length']
            else:
                try:
                    object_length, _ = self.__get_object_data_length(self.message[length:], part_structure)
                    length += object_length
                except:
                    return None
        return length

    def __get_object_data_length(self, part_data, part_structure):
        number_of_objects, rest_data = self.unpack_self_defined_int(part_data)
        number_of_objects_length = len(part_data) - len(rest_data)
        object_structure = self.protocol[part_structure['type']][part_structure['name']]['structure']
        object_structure_length = self.calc_structure_length(structure=object_structure)
        return object_structure_length * number_of_objects + number_of_objects_length, rest_data

    def __get_object_data(self, data, part_structure):
        object_data_length, data = self.__get_object_data_length(data, part_structure)
        return self.__get_data_part(data, object_data_length)

    def unpack_list(self, **kwargs):
        structure = self.protocol['list'][kwargs['part_name']]['structure']
        structure_length = self.calc_structure_length(structure)
        data = kwargs['part_data']
        unpack_obj_list = []
        while data:
            obj_data, data = self.__get_data_part(data, structure_length)
            unpack_obj_list.append(self.unpack_package(obj_data, structure))
        return unpack_obj_list

    def get_request_length(self):
        return len(self.message)

    def unpack_type(self, part_data, part_structure):
        if not 'type' in part_structure:
            return {part_structure['name']: part_data}
        unpack_type_function = getattr(self, 'unpack_{}'.format(part_structure['type']))
        unpack_data = unpack_type_function(part_name=part_structure['name'], part_data=part_data)
        if isinstance(unpack_data, dict):
            return unpack_data
        return {part_structure['name']: unpack_data}

    def pack_list(self, **kwargs):
        length = len(kwargs['part_data'])
        packed_length = self.pack_self_defined_int(length)
        return packed_length + b''.join(kwargs['part_data'])

    def unpack_hpn_servers_protocol(self, **kwargs):
        int_data, _ = self.unpack_self_defined_int(kwargs['part_data'])
        unpack_data = self.unpack_mapping('hpn_servers_protocol', int_data)
        return {kwargs['part_name']: unpack_data}

    def unpack_hpn_ping(self, **kwargs):
        return {'hpn_ping': self.unpack_int(**kwargs)}

    def pack_hpn_ping(self, **kwargs):
        return self.int_to_hex(kwargs['part_data'], 1)

    def pack_mapping(self, **kwargs):
        mapping_name = kwargs['part_structure']['name']
        mapping_data = kwargs['part_data']
        structure = self.protocol['mapping'][mapping_name]['structure']
        mapping_data_int = structure[mapping_data]
        return self.pack_self_defined_int(mapping_data_int)

    def unpack_mapping(self, **kwargs):
        mapping_data_int, _ = self.unpack_self_defined_int(kwargs['part_data'])
        structure = self.protocol['mapping'][kwargs['part_name']]['structure']
        inversion_structure = {v: k for k, v in structure.items()}
        return inversion_structure[mapping_data_int]

    def unpack_timestamp(self, **kwargs):
        return self.unpack_int(**kwargs)

    def unpack_bool_marker(self, **kwargs):
        return kwargs['part_data'] == 1

    def pack_bool(self, **kwargs):
        return b'\x01' if kwargs['part_data'] else b'\x00'

    def unpack_bool(self, **kwargs):
        return kwargs['part_data'] == b'\x01'

    def pack_addr(self, **kwargs):
        host, port = kwargs['part_data']
        return struct.pack(self.struct_addr, *(map(int, host.split('.'))), port)

    def unpack_addr(self, **kwargs):
        res = struct.unpack(self.struct_addr, kwargs['part_data'])
        host = '.'.join(map(str, res[:4]))
        port = res[4]
        return (host, port)

    def pack_markers(self, **kwargs):
        markers = 0
        for part_name in kwargs['part_name_list']:
            marker_description = self.protocol['marker'][part_name]
            marker_value = kwargs['part_data'][part_name]
            markers ^= self.make_marker(marker_value, marker_description, kwargs['part_structure'])
        return self.int_to_hex(markers, kwargs['part_structure']['length'])

    def make_marker(self, marker_value, marker_description, part_structure):
        part_structure_length_bits = part_structure['length'] * 8
        left_shift = part_structure_length_bits - marker_description['start_bit'] - marker_description['length']
        return marker_value << left_shift

    @classmethod
    def get_packed_addr_length(cls):
        return struct.calcsize(cls.struct_addr)

    @classmethod
    def init_protocol(cls, protocol):
        cls.convert_protocol_to_dict(protocol)
        cls.recovery_protocol_contraction(protocol)
        return protocol

    @classmethod
    def convert_protocol_to_dict(cls, protocol):
        for key in ['package', 'marker', 'list', 'contraction', 'mapping']:
            items_list = protocol[key]
            items_dict = {}
            for item in items_list:
                items_dict[item['name']] = item
            protocol[key] = items_dict

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

        for package_protocol in protocol['package'].values():
            define_name_list = get_define_name_list(package_protocol)
            found_define_contraction = set(contractions_name) & set(define_name_list)
            if found_define_contraction:
                recovery_define(package_protocol, found_define_contraction)

            structures_name_list = get_structures_name_list(package_protocol)
            found_structure_contraction = set(contractions_name) & set(structures_name_list)
            if structures_name_list:
                recovery_structure(package_protocol, found_structure_contraction)

    def pack_timestamp(self, **kwargs):
        return self.int_to_hex(kwargs['part_data'], 4)

    def unpack_markers(self, **kwargs):
        markers = {}
        for marker_name in kwargs['part_name']:
            marker_data = self.__split_markers(marker_name, kwargs['part_data'])
            markers.update(self.unpack_type(marker_data, self.protocol['marker'][marker_name]))
        return markers

    def set_marker_type(self, marker_name, marker_data):
        marker_structure = self.__get_marker_description(marker_name)
        marker_type = marker_structure.type
        if marker_type is null:
            return marker_data
        set_type_function = getattr(self, 'unpack_{}'.format(marker_type))
        return set_type_function(part_data=marker_data)

    def unpack_int_marker(self, **kwargs):
        return kwargs['part_data']

    def unpack_bool_marker(self, **kwargs):
        return kwargs['part_data'] == 1

    def __split_markers(self, marker_name, markers_data):
        marker_structure = self.protocol['marker'][marker_name]
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

    def unpack_int(self, **kwargs):
        return struct.unpack('>' + self.struct_length[len(kwargs['part_data'])], kwargs['part_data'])[0]

    def pack_int(self, **kwargs):
        return self.int_to_hex(kwargs['part_data'], kwargs['part_structure']['length'])

    def unpack_str(self, **kwargs):
        return kwargs['part_data'].decode()

    def pack_str(self, **kwargs):
        return kwargs['part_data'].encode()

    def int_to_hex(self, data, size):
        return struct.pack('>' + self.struct_length[size], data)

    def __get_data_part(self, data, length):
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
            return self.int_to_hex(data=number, size=1)
        if number <= (1 << (8*2))-1:
            return self.int_to_hex(data=0xfd, size=1) + self.pack_int(data=number, size=2)
        if number <= (1 << (8*4))-1:
            return self.int_to_hex(data=0xfe, size=1) + self.pack_int(data=number, size=4)
        if number <= (1 << (8*8))-1:
            return self.int_to_hex(data=0xff, size=1) + self.pack_int(data=number, size=8)
