# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


from time import time
import settings
from settings import logger
from crypt_tools import Tools as CryptTools
from net_pool import NetPool
from utilit import NULL
from utilit import check_border_timestamp


class Connection:
    def __init__(self, remote_addr=None, transport=None, request=None):
        #logger.debug('')
        self.transport = transport
        self.received_message_time = None
        self.sent_message_time = None
        if request:
            self.__set_time_received_message()
            self.__request = request
        if remote_addr:
            self.__set_remote_addr(remote_addr)
        NetPool().save_connection(self)


    def __eq__(self, connection):
        if self.__remote_host != connection.__remote_host:
            return False
        if self.__remote_port != connection.__remote_port:
            return False
        return True

    def __str__(self):
        return '{}:{}'.format(self.__remote_host, self.__remote_port)

    def __repr__(self):
        return '{}:{}'.format(self.__remote_host, self.__remote_port)

    def is_alive(self):
        if self.transport.is_closing():
            return False
        return True

    def last_received_message_is_over_time_out(self):
        if self.message_was_never_sent():
            return False
        if self.message_was_never_received():
            if self.last_sent_message_is_over_time_out():
                return True
            return False
        return time() - self.received_message_time > settings.peer_timeout_seconds

    def last_sent_message_is_over_ping_time(self):
        if self.message_was_never_sent():
            return False
        return time() - self.sent_message_time > settings.peer_ping_time_seconds

    def last_sent_message_is_over_time_out(self):
        return time() - self.sent_message_time > settings.peer_timeout_seconds

    def get_time_received_message(self):
        return self.received_message_time

    def message_was_never_sent(self):
        return self.sent_message_time is None

    def message_was_never_received(self):
        return self.received_message_time is None

    def get_time_sent_message(self):
        return self.sent_message_time

    def set_time_sent_message(self, sent_message_time=NULL()):
        if sent_message_time is NULL():
            self.sent_message_time = time()
        else:
            self.sent_message_time = sent_message_time

    def __set_time_received_message(self):
        self.received_message_time = time()

    def __set_remote_addr(self, remote_addr):
        self.__remote_host, self.__remote_port = remote_addr

    def set_request(self, request):
        self.__request = request

    def get_request(self):
        return self.__request

    def update_request(self, connection):
        self.__request = connection.get_request()
        self.__set_time_received_message()

    def set_pub_key(self, pub_key):
        if pub_key is None:
            return
        self._pub_key = pub_key
        self.__fingerprint = CryptTools().make_fingerprint(pub_key)

    def get_pub_key(self):
        if not hasattr(self, '_pub_key'):
            return None
        return self._pub_key

    def get_fingerprint(self):
        return self.__fingerprint

    def get_remote_addr(self):
        return (self.__remote_host, self.__remote_port)

    def set_encrypt_marker(self, encrypt_marker):
        self._encrypt_marker = encrypt_marker

    def get_encrypt_marker(self):
        if not hasattr(self, '_encrypt_marker'):
            return settings.request_encrypted_protocol
        return self._encrypt_marker

    def set_unpack_request(self, unpack_request):
        self.unpack_request = unpack_request

    def get_unpack_request_part(self, part_name):
        return self.unpack_request[part_name]

    def send(self, response):
        self.transport.sendto(response, (self.__remote_host, self.__remote_port))
        self.set_time_sent_message()

    def shutdown(self):
        if self.transport.is_closing():
            return
        self.transport.close()
