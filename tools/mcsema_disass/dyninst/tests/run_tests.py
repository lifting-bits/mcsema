#!/usr/bin/env python

import unittest
import os
import tempfile
import shutil
import sys
import subprocess
import argparse

disass = None
lift = None
lib_dir = None
std_defs = None

class LinuxTest (unittest.TestCase):
    def setUp (self):
        assert disass is not None
        assert lift is not None
        assert lib_dir is not None
        assert std_defs is not None

        self.test_dir = tempfile.mkdtemp ()
        self.cc = "clang"

    def tearDown (self):
        shutil.rmtree (self.test_dir)

    def runTest (self, filename, *args):
        shutil.copy (filename, self.test_dir)

        source = self.test_dir + "/" + filename

        # The ".exe" suffix is arbitrary
        exe = self.test_dir + "/" + filename + ".exe"

        # Build the C file
        subprocess.check_output ([ self.cc, source, "-o", exe ], stderr = subprocess.STDOUT)

        # Generate the expected output
        expected_output = subprocess.check_output ([ exe ] + list (args), stderr = subprocess.STDOUT)

        # Disassemble the binary
        cfg = self.test_dir + "/" + filename + ".cfg"
        subprocess.check_call ([ disass, exe, "-o", cfg, "--std-defs", std_defs ])

        # Lift it
        bc = self.test_dir + "/" + filename + ".bc"
        subprocess.check_output ([ lift, "-os", "linux", "-arch", "amd64", "-cfg", cfg,
                                   "-entrypoint", "main", "-output", bc ], stderr = subprocess.STDOUT)

        # Recompile it
        rcexe = self.test_dir + "/" + filename + ".rc-exe"
        subprocess.check_call ([ self.cc, bc, "-o", rcexe, "-L", lib_dir, "-lmcsema_rt64" ])

        # Generate actual output
        actual_output = subprocess.check_output ([ rcexe ] + list (args), stderr = subprocess.STDOUT)

        # Check the output
        self.assertEqual (expected_output, actual_output)

        os.remove (source)
        os.remove (exe)
        os.remove (cfg)
        os.remove (bc)
        os.remove (rcexe)

    def test_all_data_array (self):
        self.runTest ("all_data_array.c")

    def test_all_globals (self):
        self.runTest ("all_globals.c")

    def test_all_stringpool (self):
        self.runTest ("all_stringpool.c")

    def test_all_switch (self):
        self.runTest ("all_switch.c", "12")

    def test_array (self):
        self.runTest ("array.c")

    def test_bubblesort (self):
        self.runTest ("bubblesort.c", "1234")

    def test_dot_product (self):
        self.runTest ("dot_product.c")

    def test_fibonacci (self):
        self.runTest ("fibonacci.c", "26")

    def test_helloworld (self):
        self.runTest ("helloworld.c")

    def test_local_array (self):
        self.runTest ("local-array.c")

    def test_matrix_vector_mult (self):
        self.runTest ("matrix_vector_mult.c")

    def test_open_close_dir (self):
        self.runTest ("open_close_dir.c", "/usr")

    def test_pointers (self):
        self.runTest ("pointers.c")

    def test_rand_and_strtol (self):
        self.runTest ("rand_and_strtol.c")

    def test_readdir (self):
        self.runTest ("readdir.c", "readdir.c", "file-that-does-not-exist")

    def test_simple_array (self):
        self.runTest ("simple_array.c")

    def test_simple_exit (self):
        self.runTest ("simple_exit.c")

    def test_simple_for_loop (self):
        self.runTest ("simple_for_loop.c")

    def test_simple_main (self):
        self.runTest ("simple_main.c")

    def test_struct (self):
        self.runTest ("struct.c")

    def test_x86_bts (self):
        self.runTest ("x86_bts.c")

    def test_x86_lodsb (self):
        self.runTest ("x86_lodsb.c")

    def test_libfoo_so (self):
        # This test needs special handling because it builds a shared library

        filename = "libfoo_foo.c"
        shutil.copy (filename, self.test_dir)
        shutil.copy ("libfoo_test.c", self.test_dir)
        source = self.test_dir + "/" + filename
        source_test = self.test_dir + "/libfoo_test.c"

        so = self.test_dir + "/" + "libfoo.so"
        subprocess.check_output ([ self.cc, source, "-o", so, "-shared", "-fPIC" ], stderr = subprocess.STDOUT)
        exe = self.test_dir + "/" + "libfoo_test"
        subprocess.check_output ([ self.cc, source_test, "-o", exe,
                                   "-L", self.test_dir, "-lfoo", "-Wl,-rpath=" + self.test_dir ],
                                 stderr = subprocess.STDOUT)
        expected_output = subprocess.check_output ([ exe ], stderr = subprocess.STDOUT)

        cfg = self.test_dir + "/" + filename + ".cfg"
        subprocess.check_call ([ disass, so, "-o", cfg, "--std-defs", std_defs ])

        bc = self.test_dir + "/" + filename + ".bc"
        subprocess.check_output ([ lift, "-os", "linux", "-arch", "amd64", "-cfg", cfg,
                                   "-entrypoint", "foo", "-entrypoint", "bar",
                                   "-entrypoint", "baz", "-entrypoint", "test",
                                   "-output", bc ], stderr = subprocess.STDOUT)

        obj = self.test_dir + "/" + "foo.o"
        subprocess.check_call ([ self.cc, bc, "-o", obj, "-c" ])
        rcexe = self.test_dir + "/" + "libfoo_test_rc"
        subprocess.check_call ([ self.cc, source_test, obj, "-L", lib_dir, "-lmcsema_rt64", "-o", rcexe ])

        actual_output = subprocess.check_output ([ rcexe ], stderr = subprocess.STDOUT)

        self.assertEqual (expected_output, actual_output)

        os.remove (source)
        os.remove (so)
        os.remove (exe)
        os.remove (cfg)
        os.remove (bc)
        os.remove (obj)
        os.remove (rcexe)

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser (
        formatter_class = argparse.RawDescriptionHelpFormatter)

    arg_parser.add_argument ('--disass',
                             help = "Path to the mcsema-dyninst-disass binary",
                             required = True)

    arg_parser.add_argument ('--lift',
                             help = "Path to the mcsema-lift binary",
                             required = True)

    arg_parser.add_argument ('--lib_dir',
                             help = "Directory that contains libmcsema_rt64.a",
                             required = True)

    arg_parser.add_argument ('--std_defs',
                             help = "File that contains standard external symbol definitions",
                             required = True)

    args, command_args = arg_parser.parse_known_args ()

    if not os.path.isfile (args.disass):
        arg_parser.error ("{} passed to --disass is not a valid file".format (args.disass))
        os.exit (1)
    else:
        disass = args.disass

    if not os.path.isfile (args.lift):
        arg_parser.error ("{} passed to --lift is not a valid file".format (args.lift))
        os.exit (1)
    else:
        lift = args.lift

    if not os.path.isdir (args.lib_dir):
        arg_parser.error ("{} passed to --lib_dir is not a valid directory".format (args.lib_dir))
        os.exit (1)
    else:
        lib_dir = args.lib_dir

    if not os.path.isfile (args.std_defs):
        arg_parser.error ("{} passed to --std_defs is not a valid file".format (args.std_defs))
        os.exit (1)
    else:
        std_defs = args.std_defs

    suite = unittest.TestLoader ().loadTestsFromTestCase (LinuxTest)
    unittest.TextTestRunner (verbosity = 2).run (suite)
