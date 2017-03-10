#!/usr/bin/env python
import os.path
import subprocess

def usage(executable):
    print "Usage:"
    print "{} <header file> [header file] [header file] ...".format(executable)

def check_prerequisites():
    if not os.path.isdir("cparser"):
        print "[+] cparser project not found, cloning cparser"
        return subprocess.call(["git", "clone", "https://github.com/GarretReece/cparser.git"])
    return 0

def process_single_file(filename):
    '''given a filename, runs that file the the preprocessor, post processor, and std def generator. 
    Returns the text of the resulting std def'''
    gcc_subproc = subprocess.Popen(["gcc", "-E", filename], stdout=subprocess.PIPE)
    post_proc = subprocess.Popen(["python","cparser/post_process_header.py"], stdin=gcc_subproc.stdout, stdout=subprocess.PIPE)
    make_def_proc = subprocess.Popen(["python","cparser/make_std_defs.py"], stdin=post_proc.stdout, stdout=subprocess.PIPE)
    gcc_subproc.stdout.close()
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
