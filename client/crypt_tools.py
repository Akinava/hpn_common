# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


import os
import json
from cryptotool import *
import settings
from settings import logger
from utilit import unpack_stream, Singleton


class Tools(Singleton):
    priv_key_length = 32
    pub_key_length = 64
    fingerprint_length = 32
    sign_length = 64

    def __init__(self):
        logger.info('')
        self.init_ecdsa()

    def init_ecdsa(self):
        logger.info('')
        if not self.get_ecdsa_from_file():
            self.generate_new_ecdsa()
            self.save_ecdsa()
        self.init_ecdh()
        self.fingerprint = self.make_fingerprint(self.ecdsa.get_pub_key())

    def init_ecdh(self):
        self.ecdh = ECDH(self.ecdsa.get_priv_key())

    def read_shadow_file(self):
        logger.info('')
        if not os.path.isfile(settings.shadow_file):
            return None
        with open(settings.shadow_file) as shadow_file:
            try:
                return json.loads(shadow_file.read())
            except json.decoder.JSONDecodeError:
                return None

    def save_shadow_file(self, data):
        logger.info('')
        with open(settings.shadow_file, 'w') as shadow_file:
            shadow_file.write(json.dumps(data, indent=2))

    def update_shadow_file(self, new_data):
        logger.info('')
        file_data = {} or self.read_shadow_file()
        if file_data is None:
            file_data = {}
        file_data.update(new_data)
        self.save_shadow_file(file_data)

    def get_ecdsa_from_file(self):
        logger.info('')
        shadow_data = self.read_shadow_file()
        if shadow_data is None:
            return False
        ecdsa_priv_key_b58 = shadow_data.get('ecdsa', {}).get('key')
        if ecdsa_priv_key_b58 is None:
            return False
        ecdsa_priv_key = B58().unpack(ecdsa_priv_key_b58)
        self.ecdsa = ECDSA(priv_key=ecdsa_priv_key)
        return True

    def generate_new_ecdsa(self):
        logger.info('')
        self.ecdsa = ECDSA()

    def save_ecdsa(self):
        logger.info('')
        ecdsa_priv_key = self.ecdsa.get_priv_key()
        ecdsa_priv_key_b58 = B58().pack(ecdsa_priv_key)
        ecdsa_pub_key = self.ecdsa.get_pub_key()
        ecdsa_pub_key_b58 = B58().pack(ecdsa_pub_key)
        self.update_shadow_file(
            {'ecdsa': {
                'key': ecdsa_priv_key_b58,
                'pub_key': ecdsa_pub_key_b58}}
        )

    def get_fingerprint(self):
        return self.fingerprint

    def get_open_key(self):
        return self.ecdsa.get_pub_key()

    def make_fingerprint(self, open_key):
        return sha256(open_key)

    def sign_message(self, message):
        return self.ecdsa.sign(message)

    def check_signature(self, message):
        data_length = len(message) - self.pub_key_length - self.sign_length
        data, rest = unpack_stream(message, data_length)
        sign, pub_key = unpack_stream(rest, self.sign_length)
        ecdsa_pub = ECDSA(pub_key=pub_key)
        return ecdsa_pub.check_signature(message=data, signature=sign)

    def get_shared_key_ecdh(self, remote_pub_key):
        return self.ecdh.get_shared_key(remote_pub_key)

    def aes_encode(self, key, message):
        return AES(key).encode(message)

    def aes_decode(self, key, message):
        return AES(key).decode(message)

    def encrypt_message(self, message, remote_pub_key):
        sharedsecret = self.get_shared_key_ecdh(remote_pub_key)
        return self.aes_encode(sharedsecret, message)

    def sign_message(self, message):
        return self.ecdsa.sign(message)

    def unpack_datagram(self, connection):
        if not self.__is_encrupted(connection):
            return
        self.__decrypt_request(connection)

    def __is_encrupted(self, connection):
        if len(connection.get_request()) <= AES.bs:
            return False
        if self.fingerprint in connection.get_request():
            return False
        return True

    def __decrypt_request(self, connection):
        shared_key = self.get_shared_key_ecdh(connection.get_pub_key())
        datagram = self.aes_decode(shared_key, connection.get_request())
        logger.info('%s' % (datagram.hex()))
        connection.set_request(datagram)

    def encrypt_message(self, **kwargs):
        package_protocol = kwargs['package_protocol']
        connection = kwargs['connection']
        message = kwargs['message']
        if package_protocol['encrypted'] is False and package_protocol['signed'] is False:
            return message
        if connection.get_encrypt_marker() is True and package_protocol['encrypted'] is True:
            return self.encrypt_message(message, connection.get_pub_key())
        if package_protocol['signed'] is True or package_protocol['encrypted'] is True:
            return self.sign_message(message)
