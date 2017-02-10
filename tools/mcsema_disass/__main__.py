#!/usr/bin/env python
# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

import argparse
import os
import shutil
import sys
import tempfile
import traceback


def main(args=None):
  arg_parser = argparse.ArgumentParser()
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
      help='Name of the OS. Valid names are linux, windows.',
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

  args, command_args = arg_parser.parse_known_args()

  if not os.path.isfile(args.binary):
    arg_parser.error("{} passed to --binary is not a valid file.".format(
        args.binary))
    return 1

  if args.arch not in ('x86', 'amd64'):
    arg_parser.error("{} passed to --arch is not supported.".format(args.arch))
    return 1

  if args.os not in ('linux', 'windows'):
    arg_parser.error("{} passed to --os is not supported.".format(args.os))

  args.binary = os.path.abspath(args.binary)
  args.output = os.path.abspath(args.output)
  args.log_file = os.path.abspath(args.log_file)

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
      ret = ida.disass.execute(args, command_args)

    else:
      arg_parser.error("{} passed to --disassembler is not known.".format(
          args.disassembler))

  finally:
    shutil.rmtree(workspace_dir)

  return ret


if "__main__" == __name__:
  exit(main())