# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


from utilit import JObj


class Datagram:
    def __init__(self, connection, raw_message=None):
        self.connection = connection
        self.package_protocol = None
        self.raw_message = raw_message
        if self.raw_message:
            self.connection.set_time_received_message()
        self.decrypted_message = None
        self.unpack_message = None

    def set_raw_message(self, raw_message):
        self.raw_message = raw_message

    def set_decrypted_message(self, decrypted_message):
        self.decrypted_message = decrypted_message

    def set_unpack_message(self, unpack_message):
        self.unpack_message = unpack_message

    def set_package_protocol(self, package_protocol):
        self.package_protocol = package_protocol
