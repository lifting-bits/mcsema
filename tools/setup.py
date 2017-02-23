#!/usr/bin/env python
# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from setuptools import setup, find_packages

setup(name="mcsema-disass",
      description="Binary program disassembler for McSema.",
      version="0.0.1",
      url="https://github.com/trailofbits/mcsema",
      author="Trail of Bits",
      author_email="mcsema@trailofbits.com",
      license='BSD 3-clause "New" or "Revised License"',
      packages=['mcsema_disass', 'mcsema_disass.ida', 'mcsema_disass.defs'],
      package_data={
        "mcsema_disass.defs": ["linux.txt", "windows.txt"]},
      entry_points={
        "console_scripts": [
          "mcsema-disass = mcsema_disass.__main__:main"
        ]})
