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
import shutil
import sys

tags_dir="tags"

new = 0
exclusive = 1

def make_dir(path):
    print(" > Creating directory: " + path)
    try:
        os.makedirs(path)
    except:
        print("[Error] could not create directory " + path)


def is_batch_dir_sane(batch_name):
    for filename in os.listdir(batch_name):
        filename, extension =  os.path.splitext(batch_name)
        if extension != "cfg" or os.path.isdir(filename):
            return False
    return True

def get_binaries_from_flavours(flavors):
    binaries = []

    for filename in os.listdir(tags_dir):
        binary_name = filename.split('.')[0]

        with open(os.path.join(tags_dir, filename)) as f:
            for line in f:
                if line.rstrip("\n") in flavors:
                    print(" > Selecting " + binary_name)
                    binaries.append(binary_name)
                    break
    return binaries

def create_batch_dir(batch, policy):
    batch_name = batch + "_cfg"
    if batch_name not in os.listdir():
        print(" > Batch name is unique")
        make_dir(batch_name)
        return new

    print(" > Batch with same name already exists")
    print(" > Selected policy is " + policy)

    if policy == "D":
        print(" > Removing old batch")
        if is_batch_dir_sane(batch_name):
            shutil.rmtree(batch_name)
            make_dir(batch_name)
        else:
            print(" > Batch folder is not sane, remove manually")
            sys.exit(1)


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

    arg_parser.add_argument(
        "--batch",
        help="Specify batch name",
        required=True)
    arg_parser.add_argument(
        "--batch_policy",
        choices=["D", "U", "C"],
        help="How to resolve already existing batch\n D: delete all old cfgs\nU: Update all\nC: create only missing",
        default="D",
        required=False)

    args, command_args = arg_parser.parse_known_args()
    print( args )
    print( command_args )

    print("Checking batch name")
    create_batch_dir(args.batch, args.batch_policy)

    print("Select all binaries, specified by flavors")
    binaries = get_binaries_from_flavours(args.flavors)

    return 0

if __name__ == '__main__':
    main()
