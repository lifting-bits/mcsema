#!/usr/bin/env python

# Copyright (c) 2018 Trail of Bits, Inc.
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
import filecmp
import os
import shutil
import subprocess
from subprocess import CalledProcessError
import sys
import tempfile
import unittest


llvm_version = 0

lift = None
bin_dir = "bin"
lib_dir = None
recompiled_dir = "recompiled"

batches = []
shared_libs = None
libc = None

cases = {}

class TCData:
    def __init__(self, basename = None, bin_p = None, recompiled_p = None):
        self.binary = bin_p
        self.recompiled = recompiled_p
        self.basename = basename
        self.total = 0
        self.success = 0

    def is_recompiled(self):
        return self.recompiled is not None

    # TODO: Maybe rework as tabular?
    def print(self):
        print(self.basename)
        if not self.is_recompiled():
            print("\tRecompilation failed: ERROR")
            return

        print("\t" + str(self.success) + "/" + str(self.total))

def get_recompiled_name(name):
    return name

# Print results of tests
def print_results(t_cases):
    for key, val in t_cases.items():
        val.print()

# Fill global variables
# TODO: Rework, this is really ugly
def check_arguments(args):
    if not os.path.isfile(args.lift):
        print("{} passed to --lift is not a valid file".format(args.lift))
        sys.exit (1)
    global lift
    lift = args.lift

    global llvm_version
    prefix, sep, llvm_version = lift.rpartition('-')

    if not os.path.isdir(args.lib_dir):
        print ("{} passed to --lib_dir is not a valid directory".format(args.lib_dir))
        sys.exit (1)
    global lib_dir
    lib_dir = args.lib_dir

    if not os.path.isdir(args.bin_dir):
        print("{} passed to --bin_dir is not a valid directory".format(args.bin_dir))
        sys.exit (1)
    bin_dir = os.path.abspath(args.bin_dir)

    if not os.path.isdir(args.shared_lib_dir):
        print("{} passed to --shared_lib_dir is not a valid directory".format(args.shared_lib_dir))
        sys.exit (1)

    global shared_libs
    shared_libs = []
    for lib_name in os.listdir(args.shared_lib_dir):
        shared_libs.append(os.path.join(args.shared_lib_dir, lib_name ))

    print(" > Shared libraries: ")
    print(shared_libs)

    if not os.path.isdir(args.libc_dir):
        print ("{} passed to --libc_dir is not a valid directory".format(args.libc_dir))
        sys.exit (1)

    global libc
    libc = ''
    for lib_name in os.listdir(args.libc_dir):
        if lib_name.endswith(".bc"):
            libc += os.path.join(args.libc_dir, lib_name + ',')

    print(" > --abi_libraries files:")
    print(libc)

    # TODO: This whole snippet can be done using argparser and some actions
    if args.batch is not None:
        for batch in args.batch:
            batch_dir = batch + "_cfg"
            if not os.path.isdir(batch_dir):
                print("{} passed to --batch is not a valid directory".format(batch))
                sys.exit(1)
            batches.append(batch_dir)

    if args.batch_dir is not None:
        for batch in args.batch_dir:
            if not os.path.isdir(batch):
                print("{} passed to --batch_dir is not a valid directory".format(batch))
                sys.exit(1)
            batches.append(batch_dir)

    if not batches:
        print("No batch is selected, exiting")
        sys.exit(0)

    print(batches)


def exec_and_log_fail(args):
    pipes = subprocess.Popen(args, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    std_out, std_err = pipes.communicate()
    ret_code = pipes.returncode

    if ret_code:
        print("** stdout:")
        print(stdout)
        print("** stderr:")
        print(stderr)
        return False
    return True



# Recompile the binary from lifted .bc
# Return None in case error happens
# Otherwise return path to the newly created binary
def build_test(cfg, build_dir):
    print("Lifting " + cfg)

    # Create build directory for given test case
    binary_base_name = os.path.splitext(os.path.basename(cfg))[0]
    bc = os.path.join( build_dir, binary_base_name + ".bc")

    # TODO: arch type
    lift_args = [ lift,
                  "-os", "linux",
                  "-arch", "amd64",
                  "-cfg", cfg,
                  "-abi_libraries", libc,
                  "-output", bc ]

    if not exec_and_log_fail(lift_args):
        return None

    # Recompile it
    lifted = os.path.join(build_dir, get_recompiled_name(binary_base_name))
    lib = lib_dir + "/"+ "libmcsema_rt64-{}.a".format(llvm_version)


    recompile_args =[ "clang-{}".format(llvm_version), bc,
                      "-o", lifted, lib,
                      "-lpthread", "-lm", "-llzma", "-ldl"] + shared_libs
    if not exec_and_log_fail(recompile_args):
        return None
    return lifted


# Base class for tests, provides basic lift functionality
# Classes that inherit from it only need to specify the tests themselves
class BaseTest(unittest.TestCase):
    # Create directories where the test will be executed
    def setUp(self):
        self.t_bin = tempfile.mkdtemp(dir=os.getcwd(), prefix="bin_t")
        self.t_recompiled = tempfile.mkdtemp(dir=os.getcwd(), prefix="recompiled_t")
        self.saved_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self.saved_cwd)
        shutil.rmtree(self.t_bin)
        shutil.rmtree(self.t_recompiled)

    # Execute the test
    # A little hack is used -> binary & recompiled binary paths are stored in cases
    # under filename as key
    # TODO: Solve it somehow better
    # Compares only stdout + stderr + return value!
    def runTest(self, filename, args, files):
        # It should be guaranteed that cases contains TCData
        tc = cases[filename]

        # Unfortunately there is no way to create files in respective test dirs
        # in setUp since filename is not available there
        # We need to have binaries themselves in the directories, because --help often prints
        # the whole path
        os.symlink(tc.binary, os.path.join(self.t_bin, filename))
        os.symlink(tc.recompiled, os.path.join(self.t_recompiled, filename))

        # These cannot be returned from main
        original_ret = 2048
        lifted_ret = 2048

        expected_output = "__mcsema_error"
        actual_output = "__mcsema_error"

        if files:
            print("Copying test files:")
            for f in files:
                base_name = os.path.basename(f)
                f_name = os.path.join(self.t_recompiled, base_name)
                b_name = os.path.join(self.t_bin, base_name)
                shutil.copyfile(f, f_name)
                shutil.copyfile(f, b_name)
            print("Test files copied")

        # Generate the expected output
        os.chdir(self.t_bin)

        original_pipes = subprocess.Popen(
                [filename] + args, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        original_std_out, original_std_err = original_pipes.communicate()
        original_ret = original_pipes.returncode


        # Generate actual output
        os.chdir(self.t_recompiled)

        lifted_pipes = subprocess.Popen(
                [filename] + args, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        lifted_std_out, lifted_std_err = lifted_pipes.communicate()
        lifted_ret = lifted_pipes.returncode

        # Asserts on stderr, stdout, return value
        self.assertEqual(original_ret, lifted_ret)
        self.assertEqual(
                original_std_out,
                lifted_std_out)
        self.assertEqual(
                original_std_err,
                lifted_std_err)

    # Compare files created as by-products of tests (e.g output of gzip)
    def check_files(self, name):
        base_name = os.path.basename(name)
        actual = os.path.join(self.t_recompiled, base_name)
        expected = os.path.join(self.t_bin, base_name)
        self.assertTrue(filecmp.cmp(expected, actual))

    # Wrapper around tests, used for test counting
    def wrapper(self, filename, args, files):
        cases[filename].total += 1
        self.runTest(filename, args, files)
        cases[filename].success += 1

# IMPORTANT: Each test must obey following naming convention!
# class name = name of the tested binary + _suite
# This fact is later used to dynamically select only tests that should be run
class echo_suite(BaseTest):

    def test_echo_h( self ):
        self.wrapper("echo", ["--help"], [] )
    def test_echo_v( self ):
        self.wrapper("echo", ["--version"], [] )
    def test_echo_hello( self ):
        self.wrapper("echo", ["Hello world!"], [] )


class gzip_suite(BaseTest):

    def test_gzip_v( self ):
        self.wrapper( "gzip", ["--version"], [] )

    def test_gzip_h( self ):
        self.wrapper( "gzip", ["--help"], [] )

    def test_gzip_does_not_exists( self ):
        self.wrapper( "gzip", ["asda"], [] )

    def test_gzip_compress( self ):
        self.wrapper( "gzip", ["-f", "./data.txt"], ["inputs/data.txt"] )
        self.check_files("data.txt.gz")

    def test_gzip_decompress( self ):
        self.wrapper( "gzip", ["-df", "./dec_data.txt.gz"], ["inputs/dec_data.txt.gz"] )
        self.check_files("dec_data.txt")

    def test_gzip_l( self ):
        self.wrapper( "gzip", ["-l", "./dec_data.txt.gz"], ["inputs/dec_data.txt.gz"] )

class cat_suite(BaseTest):

    def test_cat_h( self ):
        self.wrapper("cat", ["--help"], [] )
    def test_cat_v( self ):
        self.wrapper("cat", ["--version"], [] )
    def test_cat_1( self ):
        self.wrapper("cat", ["data.txt"], ["inputs/data.txt"])
    def test_cat_n( self ):
        self.wrapper("cat", ["-n", "data.txt"], ["inputs/data.txt"])

# Right now batches are combined, maybe it would make sense to separate batches from each other
# that can be useful when comparing performance of frontends
def main():
    arg_parser = argparse.ArgumentParser (
        formatter_class = argparse.RawDescriptionHelpFormatter)

    arg_parser.add_argument('--lift',
                            help = "Path to the mcsema-lift binary",
                            required = True)

    arg_parser.add_argument('--lib_dir',
                            help = "Directory that contains libmcsema_rt64.a",
                            required = True)

    arg_parser.add_argument('--shared_lib_dir',
                            help = "Directory that contains shared libraries used by original binaries",
                            default = "shared_libs",
                            required = False)


    arg_parser.add_argument('--bin_dir',
                            help = "Directory that contains original binaries",
                            default = "bin",
                            required = False)


    arg_parser.add_argument('--batch',
                            help = "Batch names",
                            nargs = '+',
                            required = False)

    arg_parser.add_argument('--batch_dir',
                            help = 'Directories with cfgs',
                            nargs = '+',
                            required = False)

    arg_parser.add_argument('--libc_dir',
                            help = "Directory that contains bitcode types of external functions",
                            required = True)

    arg_parser.add_argument('--dry_run',
                            help = 'Do not run any tests',
                            required = False)


    args, command_args = arg_parser.parse_known_args ()
    check_arguments(args)

    # Create directory to store recompiled binaries
    # TemporaryDirectory() is not used, since we may want to have a look at recompiled code,
    # maybe we want some --preserve option
    test_dir = tempfile.mkdtemp(dir=os.getcwd())

    loader = unittest.TestLoader()
    suite_cases = []

    for batch in batches:
        print(" > Handling : " + batch)
        for f in os.listdir(batch):
            recompiled = build_test(os.path.join(batch, f), test_dir)

            basename = os.path.splitext(f)[0]
            tc = TCData(basename,
                        os.path.join(os.getcwd(), os.path.join(bin_dir, basename)),
                        recompiled)
            cases[basename] = tc

            # Lift failed for some reason, ignore this case
            if recompiled is None:
                continue

            # Dynamically load only test cases for binaries that were successfully lifted
            # Therefore ignored are fails and binaries not present in a batch
            # TODO: Solve missing test case class
            suite_name = basename + "_suite"
            suite_cases.append(loader.loadTestsFromTestCase(globals()[suite_name]))

    suite = unittest.TestSuite(suite_cases)
    unittest.TextTestRunner(verbosity = 2).run(suite)

    print_results(cases)

if __name__ == '__main__':
   main()
