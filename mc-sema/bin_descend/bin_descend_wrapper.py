#!/usr/bin/env python

import sys
import subprocess
from os.path import join, dirname, splitext
import os


ida_env = os.getenv("IDA_PATH")
if ida_env:
    if os.name is "posix":
        ida_name = "idal"
    else:
        ida_name = "idaq.exe"

    ida_env = join(ida_env, ida_name)

IDA_EXE = ida_env or r"C:\Program Files\IDA 6.5\idaq.exe"

cfg_py_env = os.getenv("GET_CFG_PY")

GET_CFG_PY = cfg_py_env or join(dirname(__file__), "get_cfg.py")

ARGS_TO_SKIP = ('-mc-x86-disable-arith-relaxation',
                '-mtriple',
                '-stats',
                '-v=',
                '-version',
                '-x86-asm-syntax',
                '-ignore-native-entry-points')

UNSUPPORTED_ARGS = ('-e=',)


def decommafy(arg):
    (argname, argval) = arg.split('=')
    argvals = argval.split(',')

    return argvals


def do_entry_symbol(arg):
    return_args = ['--entry-symbol']
    return_args.extend(decommafy(arg))

    return return_args

def do_func_map(arg):
    return_args = ['--std-defs']
    return_args.extend(decommafy(arg))
    return return_args


if __name__ == "__main__":

    new_args = ['--batch']


    argproc_map = { lambda x: x.startswith('-entry-symbol=') : do_entry_symbol,
                    lambda x: x.startswith('-func-map=') : do_func_map,
                    lambda x: x == '-help': lambda  y: ['--help'],
                    lambda x: x == '-d': lambda y: ['--debug'],
                  }

    input_file = None

    for arg in sys.argv[1:]:
        # skip args which are not applicable to IDAPython
        for skipme in ARGS_TO_SKIP:
            if arg.startswith(skipme):
                continue

        # alert on unsupported arguments
        for unsupp in UNSUPPORTED_ARGS:
            if arg.startswith(unsupp):
                sys.stderr.write("IDAPython CFG extraction does not support the argument: {0}\n".format(arg));
                sys.exit(-1)

        
        #Input file is special
        if arg.startswith('-i='):
            dummy, input_file = arg.split('=')

        # process other args
        for k,v in argproc_map.iteritems():
            if k(arg):
                new_args.extend(v(arg))


    # post-processing
    if input_file == None:
        sys.stderr.write("An input file is required. Specify via -i\n")
        sys.exit(-2)

    in_fname, in_ext = splitext(input_file)
    output_file = in_fname + ".cfg"

    new_args.extend(['--output', output_file])

    internal_args = [GET_CFG_PY]
    internal_args.extend(new_args)

    argstr = " ".join(internal_args)

    external_args = [IDA_EXE, "-B", "-S"+argstr, input_file]

    sys.stdout.write("Executing: {0}\n".format(str(external_args)))
    subprocess.call(external_args)
