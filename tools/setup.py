#!/usr/bin/env python

# Copyright (c) 2020 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys

os.chdir(os.path.dirname(os.path.abspath(__file__)))

from setuptools import setup, find_packages

setup(name="mcsema-disass",
      description="Binary program disassembler for McSema.",
      version="3.1.{}.{}".format(sys.version_info.major, sys.version_info.minor),
      url="https://github.com/lifting-bits/mcsema",
      author="Trail of Bits",
      author_email="mcsema@trailofbits.com",
      license='AGPLv3',
      packages=['mcsema_disass', 'mcsema_disass.ida7', 'mcsema_disass.defs'],
      install_requires=['protobuf==3.2.0', 'python-magic'],
      package_data={
        "mcsema_disass.defs": ["linux.txt", "windows.txt"]},
      entry_points={
        "console_scripts": [
          "mcsema-disass = mcsema_disass.__main__:main",
          "mcsema-disass-{} = mcsema_disass.__main__:main".format(sys.version_info.major),
          "mcsema-disass-{}.{} = mcsema_disass.__main__:main".format(sys.version_info.major,
                                                                     sys.version_info.minor),
        ]})
