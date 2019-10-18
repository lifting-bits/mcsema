# Copyright (c) 2019 Trail of Bits, Inc.
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
