#!/usr/bin/env python

import sys
import subprocess
from os.path import join, dirname, splitext
import os


IDA_ENV = os.getenv("IDA_PATH")
IDA_ARCH = "x86"

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

def set_ida_name(arch):
    valid_arches = ['x86', 'x86-64']
    if arch not in valid_arches:
        sys.stderr.write("Invalid architecture: {}. Expected one of: {}\n".format(arch, valid_arches))
        sys.exit(-3)

    if arch == 'x86-64':
        arch_suffix = "64"
    else:
        arch_suffix = ""

    if os.name == "posix":
        ida_name = "idal"
    else:
        ida_name = "idaq"

    return "".join([ida_name, arch_suffix])


def decommafy(arg):
    (argname, argval) = arg.split('=')
    argvals = argval.split(',')

    return argvals

def set_ida_arch(arg):
    global IDA_ARCH
    argn, val = arg.split('=')
    val_low = val.lower()
    IDA_ARCH = val_low

    # we only set global vars, no need to extend 
    # the args we pass on to ida itself
    return False

def do_entry_symbol(arg):
    return_args = ['--entry-symbol']
    return_args.extend(decommafy(arg))

    return return_args

def do_func_map(arg):
    return_args = []

    for entry in decommafy(arg):
        return_args.extend(['--std-defs', entry])

    return return_args


if __name__ == "__main__":

    new_args = ['--batch']


    argproc_map = { lambda x: x.startswith('-entry-symbol=') : do_entry_symbol,
                    lambda x: x.startswith('-func-map=') : do_func_map,
                    lambda x: x == '-help': lambda  y: ['--help'],
                    lambda x: x == '-d': lambda y: ['--debug'],
                    lambda x: x.startswith("-march=") : set_ida_arch,
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
                more_args = v(arg)
                if(more_args):
                    new_args.extend(more_args)


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
    
    if IDA_ENV is None:
        sys.stderr.write("Please Set IDA_PATH before calling this script\n")
        sys.exit(-4)

    exename = set_ida_name(IDA_ARCH)
    IDA_EXE = join(IDA_ENV, exename)
    external_args = [IDA_EXE, "-B", "-S"+argstr, input_file]

    sys.stdout.write("Executing: {0}\n".format(str(external_args)))
    subprocess.call(external_args)
