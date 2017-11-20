#!/usr/bin/env python
# Copyright (c) 2017 Trail of Bits, Inc.
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

import os.path
import subprocess

def usage(executable):
    print "Usage:"
    print "{} <header file> [header file] [header file] ...".format(executable)

def check_prerequisites():
    if not os.path.isdir("cparser"):
        print "[+] cparser project not found, cloning cparser"
        return subprocess.call(["git", "clone", "https://github.com/pgoodman/cparser.git"])
    return 0

def process_single_file(filename):
    '''given a filename, runs that file the the preprocessor, post processor, and std def generator. 
    Returns the text of the resulting std def'''
    cc_subproc = subprocess.Popen(["cc", "-E", filename], stdout=subprocess.PIPE)
    post_proc = subprocess.Popen(["python", "cparser/post_process_header.py"], stdin=cc_subproc.stdout, stdout=subprocess.PIPE)
    make_def_proc = subprocess.Popen(["python", "cparser/make_std_defs.py"], stdin=post_proc.stdout, stdout=subprocess.PIPE)
    cc_subproc.stdout.close()
    post_proc.stdout.close()
    make_def_stdout = make_def_proc.communicate()[0]
    return make_def_stdout

def main(args):
    if len(args) == 1:
        usage(args[0])
        return 1
    if 0 != check_prerequisites():
        print "error checking or installing prerequisites, aborting"
        return 2
    for filename in args[1:]:
        if os.path.isfile(filename):
            print process_single_file(filename)
    return 0

if __name__=='__main__':
    import sys
    sys.exit(main(sys.argv))
