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

import filecmp
import os
import shutil
import subprocess
from subprocess import CalledProcessError
import tempfile
import unittest
import io

import result_data

input_dir = "inputs"

# Base class for tests, provides basic lift functionality
# Classes that inherit from it only need to specify the tests themselves
class BaseTest(unittest.TestCase):

    cases = {}

    # Create directories where the test will be executed
    def setUp(self):
        # Parse name of the classes that inherits and get prefix that is actual name of binary
        self.name = type(self).__name__.rsplit('_', 1)[0]

        self.t_bin = tempfile.mkdtemp(dir=os.getcwd(), prefix="bin_t")
        self.t_recompiled = tempfile.mkdtemp(dir=os.getcwd(), prefix="recompiled_t")
        self.saved_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self.saved_cwd)
        shutil.rmtree(self.t_bin)
        shutil.rmtree(self.t_recompiled)

    # Copy input files for tests
    # This is separate function in case some test case needs special handling
    def copy_files(self, filename, args, files):
        if files:
            for f in files:
                base_name = os.path.basename(f)
                full_name = os.path.join(input_dir, f)
                f_name = os.path.join(self.t_recompiled, base_name)
                b_name = os.path.join(self.t_bin, base_name)
                shutil.copyfile(full_name, f_name)
                shutil.copyfile(full_name, b_name)

    def exec_test(self, t_dir, args, **kwargs):
        os.chdir(t_dir)

        stdin = kwargs.get("string", None)
        stdin = kwargs.get("filename") if stdin is None else stdin

        pipes = subprocess.Popen(
                args, stdout = subprocess.PIPE,
                stderr = subprocess.PIPE,stdin=subprocess.PIPE)
        std_out, std_err = pipes.communicate(input=stdin)
        ret_code = pipes.returncode

        if "filename" in kwargs:
            stdin.seek(0)

        return std_out, std_err, ret_code

    # Execute the test
    # A little hack is used -> binary & recompiled binary paths are stored in cases
    # under filename as key
    # TODO: Solve it somehow better
    # Compares only stdout + stderr + return value!
    def run_test(self, filename, args, files, **kwargs):
        # It should be guaranteed that cases contains TCData
        tc = BaseTest.cases[filename]
        tc.cases[self._testMethodName] = result_data.RUN

        # To avoid calling system-wide installed binaries
        filename = './' + filename

        # Unfortunately there is no way to create files in respective test dirs
        # in setUp since filename is not available there
        # We need to have binaries themselves in the directories,
        # because --help often prints the whole path
        os.symlink(tc.binary, os.path.join(self.t_bin, filename))
        os.symlink(tc.recompiled, os.path.join(self.t_recompiled, filename))

        # These cannot be returned from main
        original_ret = 2048
        lifted_ret = 2048

        expected_output = "__mcsema_error"
        actual_output = "__mcsema_error"

        self.copy_files(filename, args, files)

        # Generate the expected output
        original_std_out, original_std_err, original_ret = \
                self.exec_test(self.t_bin, [filename] + args, **kwargs)

        lifted_std_out, lifted_std_err, lifted_ret = \
                self.exec_test(self.t_recompiled, [filename] + args, **kwargs)

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
    def wrapper(self, args, files):
        self.wrapper_impl(args, files, string="")

    def wrapper_impl(self, args, files, **kwargs):
        BaseTest.cases[self.name].total += 1
        self.run_test(self.name, args, files, **kwargs)
        BaseTest.cases[self.name].success += 1


# Implements two invocations that are usually tested on everything
class BasicTest(BaseTest):

    def test_help(self):
        self.wrapper(["--help"], [])

    def test_version(self):
        self.wrapper(["--version"], [])

# IMPORTANT: Each test must obey following naming convention!
# class name = name of the tested binary + _suite
# This fact is later used to dynamically select only tests that should be run
class echo_suite(BasicTest):

    def test_echo_hello(self):
        self.wrapper(["Hello world!"], [] )


class gzip_suite(BasicTest):

    def test_gzip_does_not_exists(self):
        self.wrapper(["asda"], [])

    def test_gzip_compress(self):
        self.wrapper(["-f", "./data.txt"], ["data.txt"])
        self.check_files("data.txt.gz")

    def test_gzip_decompress(self):
        self.wrapper(["-df", "./dec_data.txt.gz"], ["dec_data.txt.gz"])
        self.check_files("dec_data.txt")

    def test_gzip_l(self):
        self.wrapper(["-l", "./dec_data.txt.gz"], ["dec_data.txt.gz"])

class cat_suite(BasicTest):
    def test_cat_1(self):
        self.wrapper(["data.txt"], ["data.txt"])
    def test_cat_n(self):
        self.wrapper(["-n", "data.txt"], ["data.txt"])

class readelf_suite(BasicTest):
    def test_readelf_all(self):
        self.wrapper(["--all", "./example_main.out"], ["example_main.out"])
    def test_readelf_syms(self):
        self.wrapper(["--syms", "./example_main.out"], ["example_main.out"])
    def test_readelf_relocs(self):
        self.wrapper(["--relocs", "./example_main.out"], ["example_main.out"])
    def test_readelf_x_rodata(self):
        self.wrapper(
            ["-x", ".rodata", "./example_main.out"],
            ["example_main.out"])

    def test_readelf_d(self):
        self.wrapper(
            ["-d", "./example_main.out"],
            ["example_main.out"])


class ls_suite(BasicTest):
    def test_ls(self):
        self.wrapper(["--adssdaadad"], [])
    def test_ls_exists(self):
        self.wrapper(["~/bin"], [])
    def test_ls_does_not_exists(self):
        self.wrapper(["dadadadadad"], [])

class awk_suite(BasicTest):
    pass

class bash_suite(BasicTest):
    pass

class grep_suite(BasicTest):
    def test_grep_test_non_ex(self):
        self.wrapper(["TMP", "./dummy.txt"], ["dummy.txt"])
    def test_grep_test_exists(self):
        self.wrapper(["TEST", "./dummy.txt"], ["dummy.txt"])
    def test_grep_i(self):
        self.wrapper(["-i","TeSt", "./dummy.txt"], ["dummy.txt"])

class ld_suite(BasicTest):
    pass

class perl_suite(BasicTest):
    pass

class sed_suite(BasicTest):
    def test_sef_del_f_line(self):
        self.wrapper(["-e", "1d", "dummy.txt"], ["dummy.txt"])
    def test_sef_del_token_line(self):
        self.wrapper(["-e", "/REGEX/d", "dummy.txt"], ["dummy.txt"])
    def test_sef_del_unex_token_line(self):
        self.wrapper(["-e", "/REGES/d", "dummy.txt"], ["dummy.txt"])

class xz_suite(BasicTest):
    def test_xz_c(self):
        self.wrapper(["-f", "./data.txt"], ["data.txt"])
        self.check_files("data.txt.xz")
    def test_xz_d_stdout(self):
        self.wrapper(["-cd","./xz_res.txt.xz"], ["xz_res.txt.xz"])

# TODO(Aiethel): We probably want this to be on demand, once it really grows
def init():
    CreateJustRunSuites([
        "complex_numbers", "complex_long_double", "complex_double", "complex_foat",
        "all_data_array", "all_globals", "all_stringpool",
        "array", "dot_product", "helloworld", "local-array", "matrix_vector_mult",
        "pointers", "rand_and_strtol",
        "simple_array", "simple_exit", "simple_for_loop", "simple_main",
        "struct", "x86_bts", "globals_and_io", "global_array", "qsort",
        "global_var", "pthread", "iostream_basics", "operator_new", "virtual", "virtual_simpler",
        "fmodf", "printf_floats"])

    CreateSimpleRunnerSuites({
        "qsort_function_ptrs": [["23"], ["43"]],
        "all_switch": [["12"], ["15"]],
        "bubblesort": [["12"], ["14"], ["0"]],
        "fibonacci": [["12"], ["26"]],
        "open_close_dir": [["/usr"], ["/qeqdadafaf"]],
        "readdir": [["readdir.c"], ["/tmp"], ["file-that-does-not-exist"]],
        "template_function_ptrs": [["42"], ["-543"]],
        })

    StdinFromString({
        "struct_func_ptr" : ["4\n4\n", "5\n5\n"]
        })

def CreateSimpleSuite(binary, args):
    suite_name = binary + "_suite"
    counter = 0
    methods = dict()
    for case in args:
        methods["test_" + str(counter)] = lambda x,case=case: x.wrapper(case, [])
        counter += 1
    globals()[suite_name] = type(suite_name, (BaseTest,), methods)

def StdinFromString(binaries):
    for binary, stdins in binaries.items():
        suite_name = binary + "_suite"
        counter = 0
        methods = dict()
        for case in stdins:
            methods["test_" + str(counter)] = lambda x, c=case: x.wrapper_impl([], [], stdin=c)
            counter += 1
        globals()[suite_name] = type(suite_name, (BaseTest,), methods)


def CreateJustRunSuites(binaries):
    for b in binaries:
        CreateSimpleSuite(b, [[]])

#binaries are map from binary names to list of arguments to be passed on cmd
def CreateSimpleRunnerSuites(binaries):
    for b, args in binaries.items():
        CreateSimpleSuite(b, args)
