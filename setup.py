#!/usr/bin/env python3

import os, sys
from distutils.core import setup

setup(
    name='systack',
    version='0.0.1',
    description='Associate system call sequences with stack traces',
    author='William Findlay',
    author_email='william.findlay@carleton.ca',
    url='https://github.com/willfindlay/systack',
    packages=['systack'],
    python_version='>=3.6',
)
