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

import argparse
import operator
import os
import queue
import threading
import shutil
import sys
import subprocess
import tempfile
from shlex import quote

import colors
import util

tags_dir="tags"
so_dir="shared_libs"
bin_dir="bin"

ALL_TAG="all"

FAIL = 0
SUCCESS = 1
IGNORED = 2

MESSAGES = { FAIL: "Fail", SUCCESS: "Success", IGNORED: "Skipped" }

INDENT = 2

log_dir_name = "logs"

def make_dir(path):
    print(" > Creating directory: " + path)
    try:
        os.makedirs(path)
    except:
        print("[Error] could not create directory " + path)


def is_batch_dir_sane(batch_name):
    for filename in os.listdir(batch_name):
        name, extension =  os.path.splitext(filename)

        fullname = os.path.join(batch_name, filename)
        if ((os.path.isfile(fullname) and extension != ".cfg") or \
           (os.path.isdir(fullname) and filename != log_dir_name)):
            return False
    return True

def is_valid_binary(binary_name):
    bin_path = os.path.join(bin_dir, binary_name)
    return os.path.isfile(bin_path)

# Return (list of filtered names, number of files that are missing)
def get_binaries_from_tags(desired):
    binaries = []
    missing = 0

    # We want to get cfg for everything
    get_all = ALL_TAG in desired

    bin2tag = util.get_bin2tags(tags_dir)

    for binary, tags in bin2tag.items():
        if get_all or any(x in desired for x in tags):
            if not is_valid_binary(binary):
                print(colors.bg_yellow(
                    " > Skipping " + binary+ " : file missing"))
                missing = missing + 1
            else:
                print(" > Selecting " + binary)
                binaries.append(binary)

    return (binaries, missing)

def create_batch_dir(batch, policy):
    batch_name = batch + "_cfg"
    if batch_name not in os.listdir():
        print(" > Batch name is unique")
        make_dir(batch_name)
        make_dir(os.path.join(batch_name, log_dir_name))
        return batch_name

    print(" > Batch with same name already exists")
    print(" > Selected policy is " + policy)

    if policy == "D":
        print(" > Removing old batch")
        if is_batch_dir_sane(batch_name):
            shutil.rmtree(batch_name)
            make_dir(batch_name)
            make_dir(os.path.join(batch_name, log_dir_name))
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
    if not os.path.isdir(so_dir):
        print(" > Creating " + so_dir)
        os.mkdir(so_dir)

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
    is_pie = 'LSB shared object' in res or 'Mach-O 64' in res or 'LSB pie executable' in res
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


def dyninst_frontend(binary, cfg, args, log_file):
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

    # TODO: This is too verbose for normal output
    #print(" \t> " + " ".join(disass_args))

    ret = subprocess.call(disass_args)
    if ret:
        return FAIL
    return SUCCESS

# TODO: Testing REQUIRED
def ida_frontend(binary, cfg, args, log_file):
    address_size, arch, is_pie = binary_info(binary)

    disass_args = [
        'mcsema-disass',
        '--arch', arch,
        '--os', 'linux',
        '--binary', quote(binary),
        '--output', quote(cfg),
        '--entrypoint', 'main',
        '--log_file', log_file,
        '--disassembler', args.path_to_disass]

    if is_pie:
        disass_args.append("--pie_mode")

    print(" \t> " + " ".join(disass_args))
    ret = subprocess.call(disass_args)
    if ret:
        return FAIL
    return SUCCESS

def binja_frontend(binary, cfg, args, log_file):
    print(" > Not implemented")
    sys.exit(1)


# TODO: We may want for each file to be lifted in separate directory and on a copy
# (in the case frontend is broken and modifies the original itself)
def get_cfg(*t_args, **kwargs):
    todo, args, lifter, result = t_args

    while not todo.empty():

        try:
            binary, cfg = todo.get()
        except queue.Empty:
            return

        bin_path = os.path.join(bin_dir, binary)

        print("\n > Processing " + bin_path)
        update_shared_libraries(bin_path)

        log_file = os.path.join(args.batch + "_cfg", log_dir_name, binary + ".log")
        result[binary] = lifter(bin_path, cfg, args, log_file)

# TODO: Handle other frontends
def get_lifter(disass):
    if disass == "dyninst":
        return dyninst_frontend
    if disass == "ida":
        return ida_frontend
    print(" > Support for chosen frontend was not implemented yet!")
    sys.exit(1)

def print_result(result, missing):
    print("\nResults:")
    stat = dict()
    for key, val in sorted(result.items(), key=operator.itemgetter(0)):
        print(key.ljust(30).rjust(30 + INDENT) + colors.get_bin_result(val) +
              (MESSAGES[val]).rjust(5) + colors.clean())
        if val in stat:
            stat[val] += 1
        else:
            stat[val] = 1
    print("\nTotal:")
    for key, val in MESSAGES.items():
        print(val)
        if key not in stat:
            print(" " * INDENT, str(0))
        else:
            print(" " * INDENT, stat[key])
    print("\nMissing:")
    print(" " * INDENT, missing)

def main():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument(
        "--disass",
        help='Frontend tobe used: ida | binja | dyninst',
        choices=["ida", "binja", "dyninst"],
        required=True)

    arg_parser.add_argument(
        "--path_to_disass",
        help="Path to disassembler, needed in case ida is chosen as frontend",
        default=None,
        required=False)

    arg_parser.add_argument(
        "--tags",
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

    arg_parser.add_argument(
        '--jobs',
        help = "Number of threads to use",
        default = 1,
        required = False)

    args, command_args = arg_parser.parse_known_args()


    if args.disass == "ida":
        if args.path_to_disass is None:
            print("IDA frontend is selected but --path_to_disass is not")
            sys.exit(1)
        if not os.path.isfile(args.path_to_disass):
            print("IDA frontend is selected but --path_to_disass is not a file")
            sys.exit(1)

    print("Checking batch name")
    batch_dir = create_batch_dir(args.batch, args.batch_policy)

    print("Select all binaries, specified by tags")
    binaries, missing = get_binaries_from_tags(args.tags)

    result = dict()
    print("\nIterating over binaries")

    todo = queue.Queue()

    for b in binaries:
        cfg = os.path.join(batch_dir, b + ".cfg")
        if args.batch_policy == "C" and os.path.isfile(cfg):
            print(" \t> " + cfg + " is already present, not updating")
            result[b] = IGNORED
        else:
            todo.put((b, cfg))

    threads = []
    for i in range(int(args.jobs)):
        t = threading.Thread(
                target=get_cfg, args=(todo, args, get_lifter(args.disass), result))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print_result(result, missing)

    return 0

if __name__ == '__main__':
    main()
