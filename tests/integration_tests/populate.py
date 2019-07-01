#!/usr/bin/env python
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
import shutil
import stat

tags_dir = "tags"
bin_dir = "bin"

def try_find(locations, basename):
    for p in locations:
        maybe = os.path.join(p, basename)
        if os.path.isfile(maybe):
            print(" > Found " + maybe)
            new_file = os.path.join(bin_dir, basename)
            shutil.copyfile(maybe, new_file)
            st = os.stat(new_file)
            os.chmod(new_file, st.st_mode | stat.S_IEXEC)

            return True
    return False

def main():
    # TODO: Make it portable
    locations = [ "/usr/bin", "/bin"]

    current = set()
    # If `bin` does not exist create it first
    if not os.path.isdir(bin_dir):
        os.mkdir(bin_dir)

    for f in os.listdir(bin_dir):
        current.add(f)

    for f in os.listdir(tags_dir):
        basename, ext = os.path.splitext(f)
        if basename in current:
            print(" > " + basename + " is present in " + tags_dir)
            continue

        if not try_find(locations, basename):
            print(" > " + basename + " not found anywhere")

if __name__ == '__main__':
    main()
