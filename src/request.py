# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


class Request:
    def __init__(self, raw_request, connection):
        self.connection = connection
        self.raw_request = raw_request
        self.decrypted_request = None
        self.unpack_request = None
        self.connection.set_time_received_message()

    def get_decrypted_request(self):
        return self.decrypted_request

    def set_decrypted_request(self, decrypted_request):
        self.decrypted_request = decrypted_request

    def get_unpack_request(self):
        return self.unpack_request

    def set_unpack_request(self, unpack_request):
        self.unpack_request = unpack_request

    def get_connection(self):
        return self.connection
