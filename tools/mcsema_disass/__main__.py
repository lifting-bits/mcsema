#!/usr/bin/env python
# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

import argparse
import os
import shutil
import sys
import tempfile
import traceback
import textwrap


SUPPORTED_OS = ('linux', 'windows',)
SUPPORTED_ARCH = ('x86', 'amd64',)

def main(args=None):
  arg_parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=textwrap.dedent("""\
    Additional arguments are passed to the disassembler script directly. These include:
    
      --std-defs <file>       Load additional external function definitions from <file>
      --pie-mode              Change disassembler heuristics to work on position independent code"""))

  arg_parser.add_argument(
      '--disassembler',
      help='Path to disassembler binary',
      required=True)

  arg_parser.add_argument(
      '--arch',
      help='Name of the architecture. Valid names are x86, amd64.',
      required=True)

  arg_parser.add_argument(
      '--os',
      help='Name of the OS. Valid names are {}'.format(SUPPORTED_OS),
      required=True)

  arg_parser.add_argument(
      '--log_file',
      default=os.devnull,
      help='Where to write the log file.')

  arg_parser.add_argument(
      '--output',
      help='The output control flow graph recovered from this file',
      required=True)

  arg_parser.add_argument(
      '--binary',
      help='Binary to recover control flow graph from',
      required=True)

  arg_parser.add_argument(
      '--entrypoint',
      help="The entrypoint where disassembly should begin",
      required=True)

  args, command_args = arg_parser.parse_known_args()

  if not os.path.isfile(args.binary):
    arg_parser.error("{} passed to --binary is not a valid file.".format(
        args.binary))
    return 1

  if args.arch not in SUPPORTED_ARCH:
    arg_parser.error("{} passed to --arch is not supported. Valid options are: {}".format(
      args.arch, SUPPORTED_ARCH))
    return 1

  if args.os not in SUPPORTED_OS:
    arg_parser.error("{} passed to --os is not supported. Valid options are: {}".format(
      args.os, SUPPORTED_OS))

  args.binary = os.path.abspath(args.binary)
  args.output = os.path.abspath(args.output)
  args.log_file = os.path.abspath(args.log_file)

  fixed_command_args = []
  # ensure that any paths in arguments to the disassembler
  # are absolute path
  for fix_arg in command_args:
    if os.path.exists(fix_arg):
      fixed_command_args.append(os.path.abspath(fix_arg))
    else:
      fixed_command_args.append(fix_arg)

  disass_dir = os.path.dirname(os.path.abspath(__file__))
  os.chdir(disass_dir)
  sys.path.append(disass_dir)

  workspace_dir = tempfile.mkdtemp()
  temp_bin_path = os.path.join(workspace_dir, os.path.basename(args.binary))
  shutil.copyfile(args.binary, temp_bin_path)
  args.binary = temp_bin_path

  ret = 1
  try:
    if 'ida' in args.disassembler:
      import ida.disass
      ret = ida.disass.execute(args, fixed_command_args)

      # in case IDA somehow says success, but no output was generated
      if not os.path.exists(args.output) or not os.path.isfile(args.output) :
          sys.stderr.write("Could not generate a CFG. Try using the --log_file option to see an error log.\n")
          ret = 1

      # The disassembler script probably threw an exception
      elif 0 == os.path.getsize(args.output):
          sys.stderr.write("Generated an invalid (zero-sized) CFG. Please use the --log_file option to see an error log.\n")
          # remove the zero-sized file
          os.unlink(args.output)
          ret = 1

      else:
          # assume it all went well
          pass


    else:
      arg_parser.error("{} passed to --disassembler is not known.".format(
          args.disassembler))

  finally:
    shutil.rmtree(workspace_dir)

  return ret


if "__main__" == __name__:
  exit(main())
