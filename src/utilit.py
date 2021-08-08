# -*- coding: utf-8 -*-
__author__ = 'Akinava'
__author_email__ = 'akinava@gmail.com'
__copyright__ = 'Copyright © 2019'
__license__ = 'MIT License'
__version__ = [0, 0]


import json
import sys
from datetime import datetime
import logging
import settings
import get_args


class Singleton(object):
    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, '_instance'):
            cls._instance = super(Singleton, cls).__new__(cls)
        if hasattr(cls, '_initialized'):
            cls.__init__ = cls.__skip_init__
        if not hasattr(cls, '_initialized'):
            cls._initialized = True
        return cls._instance

    def __skip_init__(self, *args, **kwargs):
        return


class NULL(Singleton):
    pass


def setup_logger():
    settings.logger = logging.getLogger(__name__)
    settings.logger.setLevel(settings.logging_level)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(settings.logging_format)
    handler.setFormatter(formatter)
    settings.logger.addHandler(handler)


def now():
    return datetime.now().strftime(settings.DATA_FORMAT)


def str_to_datetime(datatime_string):
    return datetime.strptime(datatime_string, settings.DATA_FORMAT)


def check_border_with_over_flow(min, max, value):
    if min < max:
        return min < value < max
    return value > min or max > value

def read_config_file():
    with open(settings.config_file, 'r') as cfg_file:
        return json.loads(cfg_file.read())


def import_config():
    options, args = get_args.parser()
    options_items = vars(options)
    config = read_config_file()
    for k, v in config.items():
        if k in options_items and not getattr(options, k) is None:
            continue
        setattr(settings, k, v)


def import_options():
    options, args = get_args.parser()
    for key in vars(options):
        value = getattr(options, key)
        if value is None:
            continue
        setattr(settings, key, value)


def encode(text):
    if isinstance(text, str):
        return text.encode()
    if isinstance(text, bytes):
        return text
    raise Exception('Error: can\' encode, wrong type is {}'.format(type(text)))


def update_obj(src, dst):
    if isinstance(src, dict) and isinstance(dst, dict):
        return update_dict(src, dst)
    if isinstance(src, list) and isinstance(dst, list):
        return update_list(src, dst)
    return src


def update_dict(src, dst):
    for key, val in src.items():
        dst[key] = update_obj(val, dst.get(key))
    return dst


def update_list(src, dst):
    return dst + src


def setup_settings():
    setup_logger()
    import_options()
    import_config()