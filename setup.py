#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='cryfind',
    version='3.0.1',
    description='Tool to find cryptographic constants',
    install_requires=['yara-python>=3.10,<4',
                      'docopt>=0.6,<1',
                      'lief>=0.10,<1',
                      'r2pipe>=1.4,<2'],
    author='oalieno',
    author_email='jeffrey6910@gmail.com',
    license='MIT License',
    packages = find_packages(),
    scripts = ['cryfind', 'crygen']
)
