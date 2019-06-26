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

import argparse
import os


tags_dir="tags"


def get_binaries_from_flavours(flavors):
    binaries = []

    for filename in os.listdir(tags_dir):
        binary_name = filename.split('.')[0]

        with open(os.path.join(tags_dir, filename)) as f:
            for line in f:
                if line.rstrip("\n") in flavors:
                    print("> Selecting " + binary_name)
                    binaries.append(binary_name)
                    break
    return binaries

def main():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument(
        "--llvm-version",
        help="Version number MAJOR.MINOR of the LLVM toolchain",
        required=True)

    arg_parser.add_argument(
        "--disass",
        help='Path to disassembler, or just "binja" (if installed) or "dyninst"',
        required=True)

    arg_parser.add_argument(
        "--flavors",
        help="Flavors to be lifted",
        nargs="+",
        required=True)

    arg_parser.add_argument(
        "--dry_run",
        help="Should actual commands be executed?",
        default=False,
        required=False)

    args, command_args = arg_parser.parse_known_args()
    print( args )
    print( command_args )

    binaries = get_binaries_from_flavours(args.flavors)

    return 0

if __name__ == '__main__':
    main()
