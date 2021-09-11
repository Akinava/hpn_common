# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


from utilit import JObj

class Request:
    def __init__(self, connection, raw_request=None):
        self.decrypted_request = None
        self.unpack_request = None
        self.package_protocol = None
        self.connection = connection
        self.raw_request = raw_request
        if self.raw_request:
            self.connection.set_time_received_message()

    def set_decrypted_request(self, decrypted_request):
        self.decrypted_request = decrypted_request

    def set_unpack_request(self, unpack_request):
        self.unpack_request = JObj(unpack_request)

    def set_package_protocol(self, package_protocol):
        self.package_protocol = JObj(package_protocol)
