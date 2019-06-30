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
import subprocess
import tempfile
from shlex import quote


tags_dir="tags"
so_dir="shared_libs"
bin_dir="bin"

FAIL = 0
SUCCESS = 1
IGNORED = 2

MESSAGES = { FAIL: "Fail", SUCCESS: "Success", IGNORED: "Skipped" }
def make_dir(path):
    print(" > Creating directory: " + path)
    try:
        os.makedirs(path)
    except:
        print("[Error] could not create directory " + path)


def is_batch_dir_sane(batch_name):
    for filename in os.listdir(batch_name):
        name, extension =  os.path.splitext(filename)
        if extension != ".cfg" or os.path.isdir(filename):
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
        return batch_name

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
    return batch_name

# From lift_program.py
def binary_libraries(binary):
    try:
        res = subprocess.check_output(['ldd', binary]).decode()
    except:
        print(" \t[W] ldd failed for " + binary)
        return

    for line in res.split("\n"):
        if "=>" not in line:
            continue
        name, path_and_addr = line.split(" => ")
        path_and_addr = path_and_addr.strip(" ")
        if not path_and_addr.startswith("/"):
            continue

        lib = " ".join(path_and_addr.split(" ")[:-1])
        lib = os.path.realpath(lib)

        if os.path.isfile(lib):
            yield name.strip(), lib


def update_shared_libraries(binary):
    for name, path in binary_libraries(binary):
        if name in os.listdir(so_dir):
            continue

        sym_name = os.path.join(so_dir, name)

        try:
            print(" \t> " + sym_name + " => " + path)
            os.symlink(path, sym_name)
        except:
            pass

# From lift_program.py
# Most likely there will be only x86-64 binaries for the time being,
# but it won't hurt to have it in place once we decide to add another tests
def binary_info(binary):
    res = subprocess.check_output(['file', binary]).decode()
    is_pie = 'LSB shared object' in res or 'Mach-O 64' in res
    address_size = 64

    if 'aarch64' in res:
        arch = 'aarch64'
    elif 'x86-64' in res or 'x86_64' in res:
        arch = 'amd64_avx'
    elif 'x86' in res:
        arch = 'x86_avx'
        address_size = 32
    else:
        raise Exception("Unknown architecture for file type {}".format(res))

    return address_size, arch, is_pie


def dyninst_frontend(binary ,cfg, args):
    address_size, arch, is_pie = binary_info(binary)

    disass_args = [
        "mcsema-dyninst-disass",
        "--arch", arch,
        # TODO: Portability
        "--os", "linux",
        "--binary", quote(binary),
        "--output", quote(cfg),
        "--entrypoint", "main",
        "--std_defs", args.std_defs ]

    if is_pie:
        disass_args.append("--pie_mode")
        # TODO: May not be needed
        disass_args.append("true")

    print(" \t> " + " ".join(disass_args))
    ret = subprocess.call(disass_args)
    if ret:
        return FAIL
    return SUCCESS


# TODO: We may want for each file to be lifted in separate directory and on a copy
# (in the case frontend is broken and modifies the original itself)
def get_cfg(binary, cfg, args, lifter):
    bin_path = os.path.join(bin_dir, binary)
    print(" > Processing " + bin_path)
    update_shared_libraries(bin_path)

    return lifter(bin_path, cfg, args)

# TODO: Handle other frontends
def get_lifter(disass):
    if disass == "dyninst":
        return dyninst_frontend
    print(" > Support for chosen frontend was not implemented yet!")
    sys.exit(1)

def print_result(result):
    print("Results:")
    stat = dict()
    for key, val in result.items():
        print("\t" + key + " " + MESSAGES[val])
        if val in stat:
            stat[val] += 1
        else:
            stat[val] = 1
    print("Total:")
    for key, val in MESSAGES.items():
        print(val)
        if key not in stat:
            print(0)
        else:
            print(stat[key])

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

    arg_parser.add_argument(
        "--std_defs",
        help="In case frontend still supports/needs it, can be found with McSema sources",
        default="../../tools/mcsema_disass/defs/linux.txt",
        required=False)

    args, command_args = arg_parser.parse_known_args()
    print( args )
    print( command_args )

    print("Checking batch name")
    batch_dir = create_batch_dir(args.batch, args.batch_policy)

    print("Select all binaries, specified by flavors")
    binaries = get_binaries_from_flavours(args.flavors)

    result = dict()
    print("Iterating over binaries")
    for b in binaries:
        cfg = os.path.join(batch_dir, b + ".cfg")
        if args.batch_policy == "C" and os.path.isfile(cfg):
            print(" \t> " + cfg + " is already present, not updating")
            result[b] = IGNORED
        else:
            result[b] = get_cfg(b, cfg, args, get_lifter(args.disass))

    print_result(result)

    return 0

if __name__ == '__main__':
    main()