import unittest
import sys
import tempfile
import os
import subprocess
import time
import shutil
import platform
import json
import base64

DEBUG = False

def b64(f):
    """ Base64 encodes the file 'f' """

    with open(f, 'r') as infile:
        return base64.b64encode(infile.read())

class LinuxTest(unittest.TestCase):
    """ Test translating CFGs created from Linux binaries 
        When this test runs on Linux, it will also attempt to
        rebuild the bitcode to new, and to run the new binaries.
    """
    def setUp(self):
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()
        self.archdirs = {}

        # we are testing linux binaries
        self.os = "linux"
        self.on_test_os = platform.system().lower() == self.os

        if not self.on_test_os:
            msg = "WARNING: Running {} tests on {}. Some tests will be disabled."
            sys.stderr.write(msg.format(self.os, platform.system()))

        for arch in ["x86", "amd64"]:
            self.archdirs[arch] = os.path.join(self.test_dir, arch)
            os.mkdir(self.archdirs[arch])

        self.my_dir = os.path.dirname(__file__)
        self.mcsema_lift = os.path.realpath(
            os.path.join(self.my_dir, "../", "bin", "mcsema-lift"))

        if self.on_test_os:
            # we can only rebuild binaries if we are running on the same OS
            # as the test OS
            self.configs = {}
            for arch in ["x86", "amd64"]:
                configpath = os.path.join(self.my_dir, self.os, arch, "expected_outputs.json")
                with open(configpath, 'r') as jsonfile:
                    self.configs[arch] = json.load(jsonfile)

            try:
                clang_file = subprocess.check_output(["which", "clang-3.8"])
                self.clang = clang_file.strip()
            except OSError as oe:
                sys.stderr.write("Could not find clang-3.8: {}\n".format(str(oe)))
                raise oe
            except subprocess.CalledProcessError as ce:
                sys.stderr.write("Could not find clang-3.8: {}\n".format(str(ce)))
                raise ce


    def tearDown(self):
        # Remove the directory after the test
        if not DEBUG:
            shutil.rmtree(self.test_dir)

    def _sanityCheckFile(self, fname):
        self.assertTrue(os.path.exists(fname))
        self.assertGreater(os.path.getsize(fname), 0)

    def _runWithTimeout(self, procargs, timeout=1200, stdout=None, stderr=None):

        if not DEBUG:
            errfile = os.devnull
        else:
            errfile = os.path.join(self.test_dir, "errfile")

        if not DEBUG:
            outfile = os.devnull
        else:
            outfile = os.path.join(self.test_dir, "outfile")

        with open(errfile, "w") as err_devnull:
            with open(outfile, "w") as out_devnull:
                if DEBUG:
                    sys.stderr.write("executing: {}\n".format(" ".join(procargs)))
                po = subprocess.Popen(procargs, stderr=stderr or err_devnull, stdout=stdout or out_devnull)
                secs_used = 0

                while po.poll() is None and secs_used < timeout:
                    time.sleep(1)
                    sys.stderr.write("~")
                    secs_used += 1

        # took less than timeout
        self.assertLessEqual(secs_used, timeout)

        # successfully exited
        if po.returncode != 0 and errfile != os.devnull:
            errcontent = open(errfile, 'r').read()
            sys.stderr.write("Return code not zero!. Stderr said:\n{}".format(errcontent))
        self.assertEqual(po.returncode, 0)
        sys.stderr.write("\n")

    def _runShell(self, shellargs, stdout=None, stderr=None):

        with open(os.devnull, "w") as devnull:
            if DEBUG:
                sys.stderr.write("executing: {}".format(shellargs).encode('string_escape'))
                sys.stderr.write("\n")
            subprocess.check_call(shellargs, stderr=stderr or devnull, stdout=stdout or devnull, shell=True)

    def _runAMD64Test(self, testname, entrypoint="main", buildargs=None):
        self._runArchTest("amd64", testname, entrypoint, buildargs)

    def _runX86Test(self, testname, entrypoint="main", buildargs=None):
        self._runArchTest("x86", testname, entrypoint, buildargs)

    def _compileBitcode(self, arch, infile, outfile, extra_args=None):

        arch_lib_name = {
            "amd64": "libmcsema_rt64.a",
            "x86": "libmcsema_rt32.a", }

        arch_bitcode_name = {
            "amd64": "mcsema_semantics_amd64.bc",
            "x86": "mcsema_semantics_x86.bc", }

        runtime_lib = os.path.realpath(
            os.path.join(self.my_dir, "../", "lib", arch_lib_name[arch]))

        bitcode_lib = os.path.realpath(
            os.path.join(self.my_dir, "../", "lib", arch_bitcode_name[arch]))

        flags = {
            "amd64": "-m64",
            "x86": "-m32", }

        self.assertTrue(os.path.exists(self.clang))
        args = [self.clang,
                "-O3",
                flags[arch],
                "-o", outfile,
                infile,
                bitcode_lib,
                runtime_lib,
                "-lm", # this is usually needed by the external semantics
                ]

        if extra_args:
            args.extend(extra_args)

        self._runWithTimeout(args)
        self._sanityCheckFile(outfile)

    def _checkInputs(self, arch, testname, exefile):

        self.assertTrue(os.path.exists(exefile))

        # look through the functionality tests.
        # there is more than one per file
        testset = self.configs[arch][testname]
        for test in testset.iterkeys():
            #skip comments
            if test.startswith("_"):
                continue

            # use the same arguments to the lifted program as to the original
            # the original args are stored in the config
            if 'args' in testset[test]:
                progargs = [exefile]
                progargs.extend(testset[test]['args'])
                testfunction = self._runWithTimeout
            elif 'shell' in testset[test]:
                progargs = testset[test]['shell']
                progargs = progargs.replace("#PROGNAME", exefile)
                testfunction = self._runShell
            else:
                raise RuntimeError("No 'args' or 'shell' item for test {}".format(testname))

            # create files to hold stdin/stdout
            stdout = os.path.join(self.archdirs[arch], testname + ".stdout")
            stderr = os.path.join(self.archdirs[arch], testname + ".stderr")
            #ensure we use fresh files
            for f in [stdout, stderr]:
                if os.path.exists(f):
                    os.unlink(f)

            # run the program
            with open(stdout, 'w') as outf:
                with open(stderr, 'w') as errf:
                    testfunction(progargs, stdout=outf, stderr=errf)

            self.assertTrue(os.path.exists(stdout))
            have_stdin = b64(stdout)
            self.assertEqual(have_stdin, testset[test]['expected_stdout'])
            self.assertTrue(os.path.exists(stderr))
            have_stderr = b64(stderr)
            self.assertEqual(have_stderr, testset[test]['expected_stderr'])

    def _runArchTest(self, arch, testname, entrypoint, buildargs=None):
        # sanity check #1: lifter is built
        self._sanityCheckFile(self.mcsema_lift)
        cfg_file = os.path.abspath( os.path.join(self.my_dir, "..", "tests", "linux", arch) )
        cfg_file = os.path.join(cfg_file, testname + ".cfg")
        # sanity check #2: we have a cfg file
        self._sanityCheckFile(cfg_file)

        # sanity check #3: arch dir exists
        self.assertTrue(os.path.isdir(self.archdirs[arch]))
        bcfile = os.path.join(self.archdirs[arch], testname + ".bc")

        # run the lifter
        args = [self.mcsema_lift,
                "--arch", arch,
                "--os", self.os,
                "--cfg", cfg_file,
                "--entrypoint", entrypoint,
                "--output", bcfile,]

        # check that the lifter works in a timely fasion
        # and returns exit code 0
        self._runWithTimeout(args)

        # check that the bitcode was created
        self._sanityCheckFile(bcfile)
        if self.on_test_os:
            # this has a .exe extension for Windows compatibility later on
            # it doesn't hurt anything on Linux
            elffile = os.path.join(self.archdirs[arch], testname + ".exe")
            self._compileBitcode(arch, bcfile, elffile, buildargs)
            self._checkInputs(arch, testname, elffile)

    def testHello(self):
        self._runX86Test("hello")
        self._runAMD64Test("hello")

    def testStringPool(self):
        self._runX86Test("stringpool")
        self._runAMD64Test("stringpool")

    def testlodsb(self):
        self._runX86Test("lodsb")
        self._runAMD64Test("lodsb")

    def testswitch(self):
        self._runX86Test("switch")
        self._runAMD64Test("switch")

    def testglobals(self):
        self._runX86Test("globals")
        self._runAMD64Test("globals")

    def testls(self):
        libs = ["-lrt",
                "-lpthread",
                "-ldl",
                "-lpcre",
                "/lib/x86_64-linux-gnu/libselinux.so.1"]
        self._runAMD64Test("ls", buildargs=libs)

    def testxz(self):
        libs = ["-lrt",
                "-llzma"]
        self._runAMD64Test("xz", buildargs=libs)

    def testgzip(self):
        self._runAMD64Test("gzip")

    def testnc(self):
        libs = ["-lbsd",
                "-lresolv"]
        self._runAMD64Test("nc", buildargs=libs)

if __name__ == '__main__':
    unittest.main(verbosity=2)

