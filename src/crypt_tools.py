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
from utilit import Singleton
from settings import logger


class Tools(Singleton):
    encrypted_marker = 1
    not_encrypted_marker = 0
    priv_key_length = 32
    pub_key_length = 64
    fingerprint_length = 32
    signature_length = 64

    def __init__(self):
        self.__init_ecdsa()

    def __init_ecdsa(self):
        if not self.__get_ecdsa_from_file():
            self.__generate_new_ecdsa()
            self.__save_ecdsa()
        self.__init_ecdh()
        self.fingerprint = self.make_fingerprint(self.ecdsa.get_pub_key())

    def __read_shadow_file(self):
        # logger.debug(settings.shadow_file)
        if not os.path.isfile(settings.shadow_file):
            return None
        with open(settings.shadow_file) as shadow_file:
            try:
                return json.loads(shadow_file.read())
            except json.decoder.JSONDecodeError:
                return None

    def __save_shadow_file(self, data):
        logger.debug(settings.shadow_file)
        with open(settings.shadow_file, 'w') as shadow_file:
            shadow_file.write(json.dumps(data, indent=2))

    def __update_shadow_file(self, new_data):
        logger.debug(settings.shadow_file)
        file_data = {} or self.__read_shadow_file()
        if file_data is None:
            file_data = {}
        file_data.update(new_data)
        self.__save_shadow_file(file_data)

    def __get_ecdsa_from_file(self):
        #logger.debug('')
        shadow_data = self.__read_shadow_file()
        if shadow_data is None:
            return False
        ecdsa_priv_key_b58 = shadow_data.get('ecdsa', {}).get('key')
        if ecdsa_priv_key_b58 is None:
            return False
        priv_key = B58().unpack(ecdsa_priv_key_b58)
        self.ecdsa = ECDSA(priv_key=priv_key)
        return True

    def __generate_new_ecdsa(self):
        logger.debug('')
        self.ecdsa = ECDSA()

    def __init_ecdh(self):
        priv_key = self.ecdsa.get_priv_key()
        self.ecdh = ECDH(priv_key=priv_key)


    def __save_ecdsa(self):
        logger.debug('')
        ecdsa_priv_key = self.ecdsa.get_priv_key()
        ecdsa_priv_key_b58 = B58().pack(ecdsa_priv_key)
        ecdsa_pub_key = self.ecdsa.get_pub_key()
        ecdsa_pub_key_b58 = B58().pack(ecdsa_pub_key)
        self.__update_shadow_file(
            {'ecdsa': {
                'key': ecdsa_priv_key_b58,
                'pub_key': ecdsa_pub_key_b58}})

    def get_fingerprint(self):
        return self.fingerprint

    def get_pub_key(self):
        return self.ecdsa.get_pub_key()

    def get_fingerprint_len(self):
        return self.fingerprint_length

    def make_fingerprint(self, pub_key):
        return sha256(pub_key)

    def get_shared_key_ecdh(self, remote_pub_key):
        return self.ecdh.get_shared_key(remote_pub_key)

    def aes_encode(self, key, message):
        return AES(key).encode(message)

    def aes_decode(self, key, message):
        return AES(key).decode(message)

    def encrypt(self, message, remote_pub_key):
        sharedsecret = self.get_shared_key_ecdh(remote_pub_key)
        return self.aes_encode(sharedsecret, message)

    def sign(self, message):
        return self.ecdsa.sign(message)

    def encrypt_message(self, response):
        if response.package_protocol.encrypted is not True and response.package_protocol.signed is not True:
            response.set_raw_message(response.decrypted_message)
            return
        if response.connection.get_encrypt_marker() is True and response.package_protocol.encrypted is True:
            raw_message = self.fingerprint
            raw_message += self.encrypt(response.decrypted_message, response.connection.get_pub_key())
            response.set_raw_message(raw_message)
            return
        if response.package_protocol.signed is True or response.package_protocol.encrypted is True:
            response.set_raw_message(self.sign(response.decrypted_message))
            return

    def unpack_datagram(self, request):
        if not self.__is_encrypted(request):
            request.set_decrypted_message(request.raw_message)
            return True
        return self.__decrypt_request(request)

    def __is_encrypted(self, request):
        if len(request.raw_message) <= AES.bs:
            return False
        if self.fingerprint in request.raw_message:
            return False
        return True

    def __get_connection_pub_key(self, request):
        pub_key = request.connection.get_pub_key()
        if pub_key is not None:
            return pub_key
        # in case if request came from another port that we get from server
        # the connection will not have a pub_key then we need to find the original
        # connection from server which has a pub_key
        fingerprint = request.raw_request[: self.fingerprint_length]
        net_pool = request.net_pool
        if net_pool.set_to_connection_pub_key(request.connection, fingerprint) is True:
            return request.connection.get_pub_key()
        return None

    def __decrypt_request(self, request):
        pub_key = self.__get_connection_pub_key(request)
        if pub_key is None:
            return False
        shared_key = self.get_shared_key_ecdh(pub_key)
        encrypted_message = request.raw_message[self.fingerprint_length:]
        decrypted_message = self.aes_decode(shared_key, encrypted_message)
        request.set_decrypted_message(decrypted_message)
        return True
