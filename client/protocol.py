# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


from crypt_tools import Tools as CryptTools
from package_parser import Parser


PROTOCOL = {
    'client_protocol_version': __version__,
    'packages': {
        'swarm_ping': {
            'name': 'swarm_ping',
            'define': [
                'verify_package_length',
                'define_swarm_ping'],
            'encrypted': False,
            'signed': False,
            'structure': [
                {'name': 'swarm_ping', 'length': 4}]},
        'swarm_peer_request': {
            'name': 'swarm_peer_request',
            'package_id_marker': 1,
            'define': [
                'verify_package_length',
                'ctr_verify_ver_id_marker_timestamp_receiver_fingerprint'],
            'encrypted': False,
            'signed': False,
            'response': 'swarm_peer',
            'structure': [
                {'name': ('major_version_marker', 'minor_version_marker'), 'length': 1, 'type': 'markers'},
                {'name': ('encrypted_request_marker', 'package_id_marker'), 'length': 1, 'type': 'markers'},
                {'name': 'receiver_fingerprint', 'length': CryptTools.fingerprint_length},
                {'name': 'timestamp', 'length': 4, 'type': 'timestamp'},
                {'name': 'requester_open_key', 'length': CryptTools.pub_key_length}]},
        'swarm_peer': {
            'name': 'swarm_peer',
            'package_id_marker': 2,
            'define': [
                'verify_package_length',
                'ctr_verify_ver_id_marker_timestamp_receiver_fingerprint'],
            'encrypted': True,
            'signed': True,
            'structure': [
                {'name': 'ctr_structure_version_id_marker_receiver_fingerprint_timestamp', 'type': 'contraction'},
                {'name': 'neighbour_open_key', 'length': CryptTools.pub_key_length},
                {'name': 'neighbour_addr', 'length': Parser.get_packed_addr_length()},
                {'name': 'disconnect_flag', 'length': 1, 'type': 'bool'}]},
        'sstn_request': {
            'name': 'sstn_request',
            'package_id_marker': 3,
            'define': [
                'verify_len_sstn_request',
                'ctr_verify_ver_id_marker_timestamp_receiver_fingerprint'],
            'encrypted': True,
            'signed': True,
            'response': 'sstn_list',
            'structure': [
                {'name': 'ctr_structure_version_id_marker_receiver_fingerprint_timestamp', 'type': 'contraction'}]
        },
        'sstn_list': {
            'name': 'sstn_list',
            'package_id_marker': 4,
            'define': [
                'verify_len_sstn_list',
                'ctr_verify_ver_id_marker_timestamp_receiver_fingerprint'],
            'encrypted': True,
            'signed': True,
            'structure': [
                {'name': 'ctr_structure_version_id_marker_receiver_fingerprint_timestamp', 'type': 'contraction'},
                {'name': 'sstn_list', 'type': 'list'}]}
    },
    'markers': {
        'encrypted_request_marker': {'name': 'encrypted_request_marker', 'start_bit': 0, 'length': 1, 'type': 'bool_marker'},
        'package_id_marker': {'name': 'package_id_marker', 'start_bit': 1, 'length': 7, 'type': 'int'},
        'major_version_marker': {'name': 'major_version_marker', 'start_bit': 0, 'length': 4, 'type': 'int'},
        'minor_version_marker': {'name': 'minor_version_marker', 'start_bit': 4, 'length': 4, 'type': 'int'},
    },
    'lists': {
        'sstn_list': {
            'name': 'sstn_list',
            'length': {'min': 1, 'max': 10},
            'structure': [
                {'name': 'sstn_open_key', 'length': CryptTools.pub_key_length},
                {'name': 'sstn_type', 'length': 1},
                {'name': 'sstn_addr', 'length': Parser.get_packed_addr_length()}]}
    },
    'contraction': {
        'ctr_verify_ver_id_marker_timestamp_receiver_fingerprint': {
            'name': 'ctr_verify_ver_id_marker_timestamp_receiver_fingerprint',
            'structure': [
                'verify_protocol_version',
                'verify_package_id_marker',
                'verify_timestamp',
                'verify_receiver_fingerprint']},
        'ctr_structure_version_id_marker_receiver_fingerprint_timestamp': {
            'name': 'ctr_structure_version_id_marker_receiver_fingerprint_timestamp',
            'structure': [
                {'name': ('major_version_marker', 'minor_version_marker'), 'length': 1, 'type': 'markers'},
                {'name': 'package_id_marker', 'length': 1},
                {'name': 'receiver_fingerprint', 'length': CryptTools.fingerprint_length},
                {'name': 'timestamp', 'length': 4, 'type': 'timestamp'},
            ]
        }
    }
}
