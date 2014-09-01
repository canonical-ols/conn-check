"""Installer for conn-check
"""

import os
cwd = os.path.dirname(__file__)
__version__ = open(os.path.join(cwd, 'conn_check/version.txt'),
                    'r').read().strip()

from setuptools import setup, find_packages


def get_requirements(pre=''):
    if pre:
        pre = '{}-'.format(pre)
    return open('{}requirements.txt'.format(pre)).readlines()


setup(
    name='conn-check',
    description='Utility/library for checking connectivity between services',
    long_description=open('README.rst').read(),
    version=__version__,
    author='James Westby, Wes Mason',
    author_email='james.westby@canonical.com, wesley.mason@canonical.com',
    url='https://launchpad.net/conn-check',
    packages=find_packages(exclude=['ez_setup']),
    install_requires=get_requirements(),
    extras_require={
        'amqp': get_requirements('amqp'),
        'postgres': get_requirements('postgres'),
        'redis': get_requirements('redis'),
    },
    package_data={'conn_check': ['version.txt', 'amqp0-8.xml']},
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'conn-check = conn_check.main:run',
        ],
    },
    license='GPL3',
    classifiers=[
        "Topic :: System :: Networking"
        "Development Status :: 4 - Beta"
        "Programming Language :: Python",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    ]
)
