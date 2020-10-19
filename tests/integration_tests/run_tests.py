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
import difflib
import filecmp
import operator
import os
import queue
import threading
import shutil
import subprocess
from subprocess import CalledProcessError
import sys
import tempfile
import unittest

import colors
import result_data
import util

llvm_version = 8

lift = None
bin_dir = "bin"
libmcsema = None
recompiled_dir = "recompiled"
tags_dir = 'tags'

batches = []
shared_libs = None
abi_lib_dir = None

def get_recompiled_name(name):
    return name

# Print results of tests
def print_results(t_cases):
    for key, val in sorted(t_cases.items(), key = operator.itemgetter(0)):
        val.print(0)
    for key, val in sorted(t_cases.items(), key = operator.itemgetter(0)):
        val.print_ces()

def log_results(result, into):
    for entry in result.failures:
        what = entry[0]
        into[what.name].cases[what._testMethodName] = result_data.FAIL

    for entry in result.errors:
        what = entry[0]
        # Do not overwrite timeouts
        if into[what.name].cases[what._testMethodName] != result_data.TIMEOUT:
            into[what.name].cases[what._testMethodName] = result_data.ERROR


# Fill global variables
# TODO: Rework, this is really ugly
def check_arguments(args):
    if not os.path.isfile(args.lift):
        print("{} passed to --lift is not a valid file".format(args.lift))
        sys.exit (1)
    global lift
    lift = args.lift

    if not os.path.isfile(args.runtime_lib):
        print ("{} passed to --runtime_lib is not a valid file".format(args.runtime_lib))
        sys.exit (1)
    global libmcsema
    libmcsema = args.runtime_lib

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

    print("\n > Shared libraries: ")
    print(shared_libs)

    if not os.path.isdir(args.abi_lib_dir):
        print ("{} passed to --abi_lib_dir is not a valid directory".format(args.abi_lib_dir))
        sys.exit (1)

    global abi_lib_dir
    abi_lib_dir = ''
    for lib_name in os.listdir(args.abi_lib_dir):
        if lib_name.endswith(".bc"):
            abi_lib_dir += os.path.join(args.abi_lib_dir, lib_name + ',')

    print("\n > --abi_libraries files:")
    print(abi_lib_dir)

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
    try:
        pipes = subprocess.Popen(args, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        std_out, std_err = pipes.communicate(timeout = 180)
        ret_code = pipes.returncode
    except subprocess.TimeoutExpired as e:
        pipes.terminate()
        print("Timeout!")
        return False

    if ret_code:
        print("** stdout:")
        print(std_out)
        print("** stderr:")
        print(std_err)
        return False
    return True

class Config:
    class Result:
        SUCCESS = 0
        LIFT_FAIL = 1
        RECOMPILE_FAIL = 2

    defaults = [ '-os', 'linux', '-arch', 'amd64' ]
    togglable = {
            'abi_libraries' : ['-abi_libraries', abi_lib_dir],
    }

    # Since strings are immutable, hotfix is needed once abi_lib_dir is set
    def _fix_excludes(self):
        flag, opt = self.togglable['abi_libraries']
        self.togglable['abi_libraries'] = (flag, abi_lib_dir)

    def __init__(self, name, src, cfg_path):
        self.name = name
        self.binary = os.path.join(bin_dir, name)
        self.config = src.rsplit('.', 2)[1]
        self.id = self.name + '.' + self.config
        self.cfg = cfg_path
        self.lift_args = []
        self.exclude_args = []
        self.tags = []
        self._fix_excludes()
        self._parse_config(src)

    def _tags(self, line):
        self.tags = line.split(' ')[1:]

    def _lift_opts(self, line):
        tokens = line.split(' ')[1:]
        # LIFT_OPTS are empty
        if not tokens:
            return

        exclude = []
        for opt in tokens:
            if not opt:
                break
            elif opt[0] == '+':
                self.lift_args.append(opt[1:])
            elif opt[0] != '!':
                self.lift_args.append(opt)
            else:
                exclude.append(opt[1:])

        for key, val in Config.togglable.items():
            if key in exclude:
                continue
            self.lift_args += val


    def _parse_config(self, src):
        print(' > Parsing', src)
        with open(os.path.join(tags_dir, src), 'r') as cfg:
            for line in cfg:
                line = line.rstrip('\n')
                header = line.split(' ', 1)[0]

                header_dispatch = {
                    'TAGS:' : Config._tags,
                    'LIFT_OPTS:' : Config._lift_opts,
                }

                if header not in header_dispatch:
                    raise Exception("Unknown header {}".format(header))
                header_dispatch[header](self, line)

    def lift(self, test_dir):
        print(" > Lifting", self.name + self.config)

        self.bc = os.path.join(test_dir, '.'.join([self.name, self.config, 'bc']))
        self.recompiled = os.path.join(test_dir, self.name + '.' + self.config)

        args = [lift] + self.defaults + self.lift_args + \
               ['-output', self.bc, '-cfg', self.cfg]
        print(args)
        if not exec_and_log_fail(args):
            return Config.Result.LIFT_FAIL

        return self.recompile()

    def recompile(self):
        compiler = None
        if 'c' in self.tags:
            compiler = "clang-{}"
        elif 'cpp' in self.tags:
            compiler = "clang++-{}"
        else:
            print(" > Cannot decide on compiler when recompiling",\
                  self.name + '.' + self.config)
            return Config.Result.RECOMPILE_FAIL

        compiler = compiler.format(llvm_version)
        args = [compiler, self.bc, '-o', self.recompiled, \
                libmcsema, '-lpthread', '-lm', '-ldl'] + shared_libs

        if not exec_and_log_fail(args):
            return Config.Result.RECOMPILE_FAIL
        return Config.Result.SUCCESS


def parallel_lift(*t_args):
    todo, test_dir, results = t_args
    while not todo.empty():
        try:
            config = todo.get()
        except queue.Empty:
            return

        res = config.lift(test_dir)
        # TODO: More fine grained log
        if res != Config.Result.SUCCESS:
            results[config.id] = result_data.TCData(config.id,config.recompiled, config.binary)

def get_configs(directory, allowed_tags, batched):
    result = []
    for f in os.listdir(directory):
        name = util.strip_whole_config(f)
        if not name or name not in batched:
            continue
        c = Config(name, f, batched[name])

        if allowed_tags is None:
            result.append(c)
        elif any(x in allowed_tags for x in c.tags):
            result.append(c)
    return result

class TestDetails:
    def __init__(self, cmd):
        self.cmd = cmd
        self.files = None
        self.stdin = None
        self.f_stdin = None
        self.check = []

    def set_files(self, files):
        self.files = files
        return self

    def set_check(self, check):
        self.check = check
        return self

    def set_f_stdin(self, f_stdin):
        self.f_stdin = f_stdin
        return self

    def set_stdin(self, stdin):
        self.stdin = stdin
        return self

    def files(self, files):
        if self.files is not None:
           raise Exception("Incorrect format of test case")
        self.files = files

    def stdin(self, stdin):
        if stdin[0] != 'F':
            self.stdin = stdin.encode()
            return
        self.f_stdin = os.path.abspath(stdin[1:])

class TestCase:
    def __init__(self, src=None):
        self.details = []
        if src is not None:
            self._parse(src)

    def _parse(self, src):
        dispatch = {
                'STDIN:' : TestDetails.stdin,
                'FILES:' : TestDetails.files,
        }
        with open(src, 'r') as f:
            for line in f:
                line = line.rstrip('\n')
                head = line.split(' ', 1)[0]
                if head in dispatch:
                    dispatch[head](self.details[-1], line.split(' ', 1)[1])
                else:
                    self.details.append(TestDetails(line.split(' ')))
        # .test was present but empty
        if not self.details:
            self.details.append(TestDetails(['']))


class Runner:
    def __init__(self, config, test_case):
        self.config = config
        self.test_case = test_case

    def set_up(self):
        self.t_bin = tempfile.mkdtemp(dir=os.getcwd(), prefix='bin_t')
        self.t_recompiled = tempfile.mkdtemp(dir=os.getcwd(), prefix='recompiled_t')
        self.sawed_cwd = os.getcwd()

        cfg = self.config
        os.symlink(os.path.abspath(cfg.binary), os.path.join(self.t_bin, cfg.name))
        os.symlink(cfg.recompiled, os.path.join(self.t_recompiled, cfg.name))

    def tear_down(self):
        os.chdir(self.sawed_cwd)
        shutil.rmtree(self.t_recompiled)
        shutil.rmtree(self.t_bin)

    def copy_files(self, detail):
        if detail.files is not None:
            for f in detail.files:
                basename = os.path.basename(f)
                full_name = f
                r = os.path.join(self.t_recompiled, basename)
                b = os.path.join(self.t_bin, basename)
                shutil.copyfile(full_name, r)
                shutil.copyfile(full_name, b)

    def compare(self, expected, actual, files):
        e_out, e_err, e_ret = expected
        a_out, a_err, a_ret = actual

        correct = True
        counterexample = ''
        # TODO: This cannot be more hacky than this
        try:
            if a_out != e_out:
                counterexample += 'stdout:\n'
                counterexample += '\tExpected:\n'
                counterexample += e_out.decode() + '\n'
                counterexample += '\tGot:\n'
                counterexample += a_out.decode() + '\n'
                correct = correct and False
            if a_err != e_err:
                counterexample += 'stderr:'+ '\n'
                counterexample += '\tExpected:'+ '\n'
                counterexample += e_err.decode()+ '\n'
                counterexample += '\tGot:'+ '\n'
                counterexample += a_err.decode()+ '\n'
                correct = correct and False
        except UnicodeDecodeError as e:
            correct = False
            counterexample += str(e) + '\n'

        if e_ret != e_ret:
            counterexample += "Return code: " + str(e_ret) + ' != ' + str(a_ret) + '\n'
            correct = correct and False

        for name in files:
            base_name = os.path.basename(name)
            actual = os.path.join(self.t_recompiled, base_name)
            expected = os.path.join(self.t_bin, base_name)
            try:
                if not filecmp.cmp(expected, actual):
                    counterexample += 'Files do not match: ' + base_name + '\n'
                    correct = correct and False
            except FileNotFoundError as e:
                counterexample += 'File {} not found/produced! '.format(base_name)
                correct = correct and False

        result = result_data.RUN if correct else result_data.FAIL
        return (result, counterexample)

    def open_stdin(self, t_dir, args, stdin):
        with open(stdin, 'rb') as f:
            r = f.read()
            return self.exec_(t_dir, args, r)

    def exec_(self, t_dir, args, stdin):
        os.chdir(t_dir)
        try:
            pipes = subprocess.Popen(
                    args, stdout=subprocess.PIPE,
                    stderr = subprocess.PIPE,
                    stdin = subprocess.PIPE)
            out, err = pipes.communicate(stdin, timeout=5)
            ret = pipes.returncode

            os.chdir(self.sawed_cwd)
            return (out, err, ret)
        except subprocess.TimeoutExpired as e:
            pipes.terminate()
            raise e


    def exec(self, detail, files):
        # To avoid calling system-wide installed binaries
        filename = './' + self.config.name

        _exec = Runner.exec_ if detail.f_stdin is None else Runner.open_stdin
        stdin = detail.f_stdin if detail.f_stdin is not None else detail.stdin

        try:
            print(detail.cmd)
            expected = _exec(self, self.t_bin, [filename] + detail.cmd, stdin)
            actual = _exec(self, self.t_recompiled, [filename] + detail.cmd, stdin)
            return self.compare(expected, actual, files)
        except subprocess.TimeoutExpired as e:
            return result_data.TIMEOUT, "Timeout"
        except FileNotFoundError as e:
            return result_data.ERROR, "File not found"

    def run(self, detail):
        self.set_up()
        self.copy_files(detail)
        result, ce = self.exec(detail, detail.check)
        self.tear_down()
        return (result, ce)


    def evaluate(self, results):
        c = self.config
        results[c.id] = result_data.TCData(c.id, c.recompiled, c.binary)
        for tc in self.test_case:
            for d in tc.details:
                result, ce = self.run(d)
                results[c.id].cases[' '.join(d.cmd)] = result
                results[c.id].total += 1
                if result == result_data.RUN:
                    results[c.id].success += 1
                else:
                    results[c.id].ces[' '.join(d.cmd)] = ce

class Tester:

    def __init__(self, configs, test_def_dir):
        # Config -> TestCase
        self.cases = {}

        for c in configs:
            self.cases[c] = []

        for f in os.listdir(test_def_dir):
            basename, ext = os.path.splitext(f)
            if ext != '.test':
                continue

            tc = TestCase(os.path.join(test_def_dir, f))
            for key, val in self.cases.items():
                if key.name == basename:
                    val.append(tc)

        for key, val in g_complex_test.items():
            for k, v in self.cases.items():
                if k.name == key:
                    tc = TestCase()
                    tc.details = val
                    v.append(tc)

    def run(self, results):
        for key, val in self.cases.items():
            print(key.id, 'number of tests:', len(val))
            r = Runner(key, val)
            r.evaluate(results)


g_complex_test = {
    "gzip" :
    [
        TestDetails(['--help']),
        TestDetails(['--version']),
        TestDetails(['-asda']),
        TestDetails(['-f', './data.txt']).set_files(['inputs/data.txt']). \
                    set_check(['data.txt.gz']),
        TestDetails(['-l', './dec_data.txt.gz']).set_files(['inputs/dec_data.txt.gz']),
        TestDetails(['-df', './dec_data.txt.gz']).set_files(['inputs/dec_data.txt.gz']).\
                    set_check(['dec_data.txt']),
        TestDetails(['']),
    ],

    "cat":
    [
        TestDetails(['--help']),
        TestDetails(['--version']),
        TestDetails(['data.txt']).set_files(['inputs/data.txt']),
        TestDetails(['-n', 'data.txt']).set_files(['inputs/data.txt']),
    ],

    "echo":
    [
        TestDetails(['--help']),
        TestDetails(['--version']),
        TestDetails(['Hello Wordl!']),
    ],


}



# Right now batches are combined, maybe it would make sense to separate batches from each other
# that can be useful when comparing performance of frontends
def main():
    arg_parser = argparse.ArgumentParser(
        formatter_class = argparse.RawDescriptionHelpFormatter)

    arg_parser.add_argument('--lift',
                            help = "Path to the mcsema-lift binary",
                            required = True)

    arg_parser.add_argument('--runtime_lib',
                            help = "Runtime library for lifted bitcode \
                                    (e.g. libmcsema-rt64-6.0.a",
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

    arg_parser.add_argument('--abi_lib_dir',
                            help = "Directory that contains bitcode types of external functions",
                            required = True)

    arg_parser.add_argument('--dry_run',
                            help = 'Do not run any tests',
                            required = False)

    arg_parser.add_argument('--save_log',
                            help = "Name of file to save result in json format",
                            required = False)

    arg_parser.add_argument('--jobs',
                            help = "Number of threads to use",
                            default = 1,
                            required = False)

    arg_parser.add_argument('--tags',
                           help = "Test only these tags from batch",
                           required = False)

    args, command_args = arg_parser.parse_known_args()
    check_arguments(args)


    # Create directory to store recompiled binaries
    # TemporaryDirectory() is not used, since we may want to have a look at recompiled
    # code, maybe we want some --preserve option
    test_dir = tempfile.mkdtemp(dir=os.getcwd())

    # basename -> path
    batched = {}
    for batch in batches:
        for f in os.listdir(batch):
            if os.path.isfile(os.path.join(batch, f)):
                    basename, ext = os.path.splitext(f)
                    batched[basename] = os.path.join(batch, f)


    configs = get_configs(tags_dir, args.tags, batched)
    _todo = queue.Queue()
    for c in configs:
        _todo.put(c)

    threads = []
    results = {}
    for i in range(int(args.jobs)):
        t = threading.Thread(target=parallel_lift, args=(_todo, test_dir, results))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    Tester(configs, tags_dir).run(results)
    print_results(results)

    return

if __name__ == '__main__':
    main()
