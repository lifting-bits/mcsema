#!/usr/bin/env python3

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

import argparse
import os
import subprocess

tags_dir = "tags"
bin_dir = "bin"
src_dir = "src"

cxx_comp = 'clang++'
cc_comp = 'clang'

def compilation(std, f):
    basename, ext = os.path.splitext(f)
    ext_map = { '.cpp' : cxx_comp,
                '.c'   : cc_comp }

    cc = ext_map.get(ext, None)
    if cc is None:
        print(" > " + f + " has unknown extension")
        return

    out = os.path.join(bin_dir, basename)
    args = [cc, os.path.join(src_dir, f), '-o', out, '-lm', '-lpthread']
    if cc == cxx_comp:
        args += ['-std=' + std]

    print(args)
    pipes = subprocess.Popen(args, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    std_out, std_err = pipes.communicate()
    ret_code = pipes.returncode

    if ret_code:
        print("*** Compilation failed ***")
        print("\n** stdout:")
        print(std_out)
        print("\n** stderr:")
        print(std_err)

def add_tags(tags_list, f):
    print(tags_list)
    basename, ext = os.path.splitext(f)
    tag_file = os.path.join(tags_dir, basename + '.tag')

    # File is already present -> just update the tag if it's missing
    present = set()
    with open(tag_file, 'a+') as reader:
        reader.seek(0)
        for line in reader:
            present.add(line.rstrip())

        for t in tags_list:
            if t not in present:
                reader.write(t + '\n')


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        '--std',
        help='C++ standard to use',
        choices=['c++11', 'c++14', 'c++17'],
        default='c++17',
        required=False)

    arg_parser.add_argument(
        '--stub_tags',
        help='Create tag files with corresponding tags, possibly empty',
        required=False,
        nargs='*')

    args, extra_args = arg_parser.parse_known_args()

    # If `bin` does not exist create it first
    if not os.path.isdir(bin_dir):
        os.mkdir(bin_dir)

    for f in os.listdir(src_dir):
        compilation(args.std, f)
        add_tags(args.stub_tags, f)

if __name__ == '__main__':
    main()
