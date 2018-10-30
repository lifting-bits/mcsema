#!/usr/bin/env python

# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from setuptools import setup, find_packages

setup(name="mcsema-disass",
      description="Binary program disassembler for McSema.",
      version="2.0",
      url="https://github.com/trailofbits/mcsema",
      author="Trail of Bits",
      author_email="mcsema@trailofbits.com",
      license='Apache 2.0',
      packages=['mcsema_disass', 'mcsema_disass.ida', 'mcsema_disass.ida7', 'mcsema_disass.defs', 'mcsema_disass.binja'],
      install_requires=['protobuf==3.2.0', 'python-magic'],
      package_data={
        "mcsema_disass.defs": ["linux.txt", "windows.txt"]},
      entry_points={
        "console_scripts": [
          "mcsema-disass = mcsema_disass.__main__:main"
        ]})
