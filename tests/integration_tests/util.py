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

def strip_whole_config(filename):
    if not filename.endswith(".config"):
        return ""
    filename = filename.rstrip(".config")
    basename, ext = os.path.splitext(filename)
    return basename

def get_binaries(directory):
    result = set()
    for f in os.listdir(directory):
        filename = strip_whole_config(f)
        if filename:
            result.add(filename)
    return result

def get_tags(config):
    with open(config, 'r') as f:
        line = f.readline().rstrip('\n')
        tokens = line.split(' ')
        if tokens[0] != 'TAGS:':
            return []
        return tokens[1:]

def get_bin2tags(directory):
    result = {}
    for f in os.listdir(directory):
        filename = strip_whole_config(f)
        if not filename:
            continue

        tags = get_tags(os.path.join(directory, f))
        if filename not in result:
            result[filename] = tags
        else:
            result[filename].append(tags)
    return result

def get_cfg(directory, name):
    return os.path.join(directory, name + '.cfg')
