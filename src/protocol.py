# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


from crypt_tools import Tools as CryptTools
from package_parser import Parser


PROTOCOL = {
    'hpn_protocol_version': __version__,
    'package': [
        {
            'name': 'hpn_ping',
            'define': [
                'verify_package_length',
                'verify_hpn_ping'],
            'encrypted': False,
            'signed': False,
            'structure': [
                {'name': 'hpn_ping', 'length': 1, 'type': 'hpn_ping'}]},
        {
            'name': 'hpn_neighbours_client_request',
            'package_id_marker': 0x00,
            'define': 'ctr_verify_len_ver_id_marker_timestamp_receiver_fingerprint',
            'encrypted': False,
            'signed': False,
            'response': 'hpn_neighbours',
            'structure': [
                {'name': ('major_hpn_protocol_version_marker', 'minor_hpn_protocol_version_marker'), 'length': 1, 'type': 'markers'},
                {'name': ('encrypted_request_marker', 'package_id_marker'), 'length': 1, 'type': 'markers'},
                {'name': 'receiver_fingerprint', 'length': CryptTools.fingerprint_length},
                {'name': 'timestamp', 'length': 4, 'type': 'timestamp'},
                {'name': 'requester_pub_key', 'length': CryptTools.pub_key_length}]},
        {
            'name': 'hpn_neighbours',
            'package_id_marker': 0x01,
            'define': 'ctr_verify_len_ver_id_marker_timestamp_receiver_fingerprint',
            'encrypted': True,
            'signed': True,
            'response': 'hpn_servers_request',
            'structure': [
                {'name': 'ctr_structure_protocol_version_id_marker_receiver_fingerprint_timestamp', 'type': 'contraction'},
                {'name': 'disconnect_flag', 'length': 1, 'type': 'bool'},
                {'name': 'hpn_clients_list', 'type': 'list'}]},
        {
            'name': 'hpn_servers_request',
            'package_id_marker': 0x02,
            'define': 'ctr_verify_len_ver_id_marker_timestamp_receiver_fingerprint',
            'encrypted': True,
            'signed': True,
            'response': 'hpn_servers_list',
            'structure': [
                {'name': 'ctr_structure_protocol_version_id_marker_receiver_fingerprint_timestamp', 'type': 'contraction'}]},
        {
            'name': 'hpn_servers_list',
            'package_id_marker': 0x03,
            'define': 'ctr_verify_len_ver_id_marker_timestamp_receiver_fingerprint',
            'encrypted': True,
            'signed': True,
            'response': 'save_hpn_servers_list',
            'structure': [
                {'name': 'ctr_structure_protocol_version_id_marker_receiver_fingerprint_timestamp', 'type': 'contraction'},
                {'name': 'hpn_servers_list', 'type': 'list'}]},
    ],
    'marker': [
        {'name': 'encrypted_request_marker', 'start_bit': 0, 'length': 1, 'type': 'bool_marker'},
        {'name': 'package_id_marker', 'start_bit': 1, 'length': 7, 'type': 'int_marker'},
        {'name': 'major_hpn_protocol_version_marker', 'start_bit': 0, 'length': 4, 'type': 'int_marker'},
        {'name': 'minor_hpn_protocol_version_marker', 'start_bit': 4, 'length': 4, 'type': 'int_marker'},
    ],
    'list': [
        {
            'name': 'hpn_servers_list',
            'length': {'max': 10},
            'structure': [
                {'name': 'hpn_servers_pub_key', 'length': CryptTools.pub_key_length},
                {'name': 'hpn_servers_protocol', 'length': 1, 'type': 'mapping'},
                {'name': 'hpn_servers_addr', 'length': Parser.get_packed_addr_length(), 'type': 'addr'}]},
        {
            'name': 'hpn_clients_list',
            'structure': [
                {'name': 'hpn_clients_pub_key', 'length': CryptTools.pub_key_length},
                {'name': 'hpn_clients_addr', 'length': Parser.get_packed_addr_length(), 'type': 'addr'}]},
    ],
    'contraction': [
        {
            'name': 'ctr_verify_len_ver_id_marker_timestamp_receiver_fingerprint',
            'structure': [
                'verify_package_length',
                'verify_hpn_protocol_version',
                'verify_package_id_marker',
                'verify_timestamp',
                'verify_receiver_fingerprint']},
        {
            'name': 'ctr_structure_protocol_version_id_marker_receiver_fingerprint_timestamp',
            'structure': [
                {'name': ('major_hpn_protocol_version_marker', 'minor_hpn_protocol_version_marker'), 'length': 1, 'type': 'markers'},
                {'name': 'package_id_marker', 'length': 1,  'type': 'int'},
                {'name': 'receiver_fingerprint', 'length': CryptTools.fingerprint_length},
                {'name': 'timestamp', 'length': 4, 'type': 'timestamp'}]}
    ],
    'mapping': [
        {'name': 'hpn_servers_protocol',
         'structure':
             {'udp': 1}
         }
    ]
}
