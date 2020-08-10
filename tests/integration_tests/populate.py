#!/usr/bin/env python3

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
import shutil
import stat

import colors
import util

tags_dir = "tags"
bin_dir = "bin"

def try_find(locations, basename):
    for p in locations:
        maybe = os.path.join(p, basename)
        if os.path.isfile(maybe):
            print(" > " + colors.green("Found " + maybe))
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
        basename = util.strip_whole_config(f)
        if not basename:
            continue

        if basename in current:
            print(" > " + basename + " is present in " + tags_dir)
            continue

        if not try_find(locations, basename):
            print(" > " + colors.red(basename + " not found anywhere"))

if __name__ == '__main__':
    main()
