#!/usr/bin/env python3

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
import subprocess

tags_dir = "tags"
bin_dir = "bin"
src_dir = "src"

cxx_comp = 'clang++'
cc_comp = 'clang'

class Config:
    allowed = ['TAGS', 'CC_OPTS', 'LD_OPTS', 'LIFT_OPTS', 'TEST']

    def __init__(self, filename):
        self.lift_opts = []
        self.tests = []
        self.cc_opts = []
        self.ld_opts = []
        self._parse_header(filename)

    def _cc_opts(self, opts):
        # Strip leading option specifier
        self.cc_opts = opts[1:]

    def _ld_opts(self, opts):
        # Strip leading option specifier
        self.ld_opts = opts[1:]

    def _lift_opts(self, opts):
        self.lift_opts.append((opts[1], opts[2:]))

    def _tags(self, opts):
        self.tags = opts[1:]

    def _test(self, opts):
        self.tests.append((opts[1:], None))

    def _stdin(self, opts):
        test, stdin = self.tests[-1]
        if stdin is not None:
            raise Exception("Two consecutive STDINs are not allowed")
        self.tests[-1] = (test, ' '.join(opts[1:]))
        print(self.tests)

    def _parse_header(self, filename):
        basename, ext = os.path.splitext(os.path.basename(filename))
        self.name = basename
        self.ext = ext
        with open(filename, 'r') as src:
            while 1:
                line = src.readline()

                line = line.rstrip('\n')
                tokens = line.split(' ')

                print(tokens)
                # Arrived at line that is not config information
                if not tokens or (tokens[0] != '/*' or tokens[-1] != '*/'):
                    return

                tokens = tokens[1:][:-1]
                dispatch = {
                        'TAGS:' : Config._tags,
                        'CC_OPTS:' : Config._cc_opts,
                        'LD_OPTS:' : Config._ld_opts,
                        'LIFT_OPTS:' : Config._lift_opts,
                        'TEST:' : Config._test,
                        'STDIN:' : Config._stdin,
                }

                if tokens[0] not in dispatch:
                    raise Exception(tokens[0] + " is not allowed as entry header!")
                dispatch[tokens[0]](self, tokens)

    def create_config(self, name, opts, dst_dir):
        with open(os.path.join(dst_dir, self.name + '.' + name + '.config'), 'w') as cfg:
            cfg.write("TAGS: " + ' '.join(self.tags) + '\n')
            cfg.write("LIFT_OPTS: " + ' '.join(opts) + '\n')

    def create_test(self, dst_dir):
        with open(os.path.join(dst_dir, self.name + '.test'), 'w') as test:
            for case, stdin in self.tests:
                test.write(' '.join(case) + '\n')
                if stdin is not None:
                    test.write('STDIN:' + stdin + '\n')


    def create_configs(self, dst_dir):
        if not self.lift_opts:
            self.create_config('default', [''], dst_dir)
        else:
            for name, opts in self.lift_opts:
                self.create_config(name, opts, dst_dir)
        self.create_test(dst_dir)

    def compile(self):
        ext_map = { '.cpp' : cxx_comp,
                    '.c'   : cc_comp }

        cc = ext_map.get(self.ext, None)
        if cc is None:
            print(" > " + self.name + " has unknown extension")
            return

        out = os.path.join(bin_dir, self.name)
        args = [cc, os.path.join(src_dir, self.name + self.ext), '-o', out] \
               + self.cc_opts + self.ld_opts

        #print(args)
        pipes = subprocess.Popen(args, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        std_out, std_err = pipes.communicate()
        ret_code = pipes.returncode

        if ret_code:
            print("*** Compilation failed ***")
            print("\n** stdout:")
            print(std_out)
            print("\n** stderr:")
            print(std_err)

def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        '--stub_tags',
        help='Create tag files with corresponding tags, possibly empty',
        required=False,
        nargs='*')

    arg_parser.add_argument(
        '--cxx',
        help='Path to C++ compiler to use',
        required=False)

    arg_parser.add_argument(
        '--cc',
        help='Path to C compiler to use',
        required=False)

    args, extra_args = arg_parser.parse_known_args()

    if args.cc is not None:
        global cc_comp
        cc_comp = args.cc

    if args.cxx is not None:
        global cxx_comp
        cxx_comp = args.cxx

    # If `bin` does not exist create it first
    if not os.path.isdir(bin_dir):
        os.mkdir(bin_dir)

    for f in os.listdir(src_dir):
        c = Config(os.path.join(src_dir, f))
        if args.stub_tags is not None:
            c.tags += args.stub_tags
        c.create_configs('tags')
        c.compile()

if __name__ == '__main__':
    main()
