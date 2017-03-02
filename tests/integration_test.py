import unittest
import sys
import tempfile
import os
import subprocess
import time
import shutil

class LinuxTest(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()
        self.archdirs = {}

        for arch in ["x86", "amd64"]:
            self.archdirs[arch] = os.path.join(self.test_dir, arch)
            os.mkdir(self.archdirs[arch])

        self.my_dir = os.path.dirname(__file__)
        self.mcsema_lift = os.path.realpath(
            os.path.join(self.my_dir, "..", "build", "mcsema-lift"))

    def tearDown(self):
        # Remove the directory after the test
        shutil.rmtree(self.test_dir)

    def _sanityCheckFile(self, fname):
        self.assertTrue(os.path.exists(fname))
        self.assertTrue(os.path.getsize(fname) > 0)

    def _runWithTimeout(self, procargs, timeout=1200):

        with open(os.devnull, "w") as devnull:
            po = subprocess.Popen(procargs, stderr=devnull, stdout=devnull)
            secs_used = 0

            while po.poll() is None and secs_used < timeout:
                time.sleep(1)
                sys.stderr.write("~")
                secs_used += 1

        # took less than timeout
        self.assertTrue(secs_used < timeout)

        # successfully exited
        self.assertTrue(po.returncode == 0)
        sys.stderr.write("\n")

    def _runAMD64Test(self, testname, entrypoint="main"):
        self._runArchTest("amd64", testname, entrypoint)

    def _runX86Test(self, testname, entrypoint="main"):
        self._runArchTest("x86", testname, entrypoint)

    def _runArchTest(self, arch, testname, entrypoint):
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
                "--os", "linux",
                "--cfg", cfg_file,
                "--entrypoint", entrypoint,
                "--output", bcfile,]

        # check that the lifter works in a timely fasion
        # and returns exit code 0
        self._runWithTimeout(args)

        # check that the bitcode was created
        self._sanityCheckFile(bcfile)

    def testHello(self):
        self._runX86Test("hello")
        self._runAMD64Test("hello")

if __name__ == '__main__':
    unittest.main()

