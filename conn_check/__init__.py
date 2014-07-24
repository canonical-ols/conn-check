#!/usr/bin/python -uWignore
"""Check connectivity to various services.
"""

import os

def get_version_string():
    return open(os.path.join(os.path.dirname(__file__),
                'version.txt'), 'r').read().strip()


def get_version():
    return get_version_string().split('.')


__version__ = get_version_string()


from twisted.internet import epollreactor
epollreactor.install()
