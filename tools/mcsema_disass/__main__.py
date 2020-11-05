#!/usr/bin/env python

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
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
import textwrap


SUPPORTED_OS = ('linux', 'macos', 'windows', 'solaris')
SUPPORTED_ARCH = ('x86', 'x86_avx', 'x86_avx512',
                  'amd64', 'amd64_avx', 'amd64_avx512',
                  'aarch64', 'sparc32', 'sparc64')

# Make sure we can do an `import binaryninja`.
def _find_binary_ninja(path_to_binaryninja):
  try:
    import binaryninja
    return True
  except:
    pass

  if not os.path.isfile(path_to_binaryninja):
    return False

  if not os.access(path_to_binaryninja, os.X_OK):
    return False

  binja_dir = os.path.dirname(path_to_binaryninja)
  sys.path.append(binja_dir)
  sys.path.append(os.path.join(binja_dir, "python"))

  try:
    import binaryninja
    return True
  except:
    return False


def main():
  arg_parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=textwrap.dedent("""\
    Additional arguments are passed to the disassembler script directly. These include:

      --std-defs <file>       Load additional external function definitions from <file>
      --pie-mode              Change disassembler heuristics to work on position independent code"""))

  arg_parser.add_argument(
      '--disassembler',
      help='Path to disassembler binary, or dyninst (binary must be in path)',
      required=True)

  arg_parser.add_argument(
      '--arch',
      help='Name of the architecture. Valid names are x86, amd64, and aarch64.',
      choices=SUPPORTED_ARCH,
      required=True)

  arg_parser.add_argument(
      '--os',
      help='Name of the OS. Valid names are {}'.format(SUPPORTED_OS),
      choices=SUPPORTED_OS,
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
      required=False)

  arg_parser.add_argument(
      '--rebase',
      help="Amount by which to rebase a binary",
      required=False,
      default=0)

  args, command_args = arg_parser.parse_known_args()

  if not os.path.isfile(args.binary):
    arg_parser.error("{} passed to --binary is not a valid file.".format(
        args.binary))
    return 1

  if args.arch.endswith("_avx"):
    args.arch = args.arch[:-4]

  if args.arch.endswith("_avx512"):
    args.arch = args.arch[:-7]

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

  new_bin_name = re.sub(r"[^a-zA-Z0-9\.]+", "_", os.path.basename(args.binary))

  workspace_dir = tempfile.mkdtemp()
  temp_bin_path = os.path.join(workspace_dir, new_bin_name)
  shutil.copyfile(args.binary, temp_bin_path)
  args.binary = temp_bin_path

  ret = 1
  try:
    if 'ida' in args.disassembler:
      import ida7.disass as disass
      ret = disass.execute(args, fixed_command_args)
      # in case IDA somehow says success, but no output was generated
      if not os.path.isfile(args.output):
        sys.stderr.write("Could not generate a CFG. Try using the --log_file option to see an error log.\n")
        ret = 1

      # The disassembler script probably threw an exception
      if 0 == os.path.getsize(args.output):
        sys.stderr.write("Generated an invalid (zero-sized) CFG. Please use the --log_file option to see an error log.\n")
        # remove the zero-sized file
        os.unlink(args.output)
        ret = 1

    elif 'dyninst' in args.disassembler:
      # TODO: This can almost certainly be done in cleaner way
      pass_args = [
        "mcsema-dyninst-disass",
        "--binary", args.binary,
        "--arch", args.arch,
        "--entrypoint", args.entrypoint,
        "--os", args.os,
        "--output", args.output,
        "--binary", args.binary,
        "--rebase", args.rebase
      ]
      subprocess.run(pass_args)
    else:
      arg_parser.error("{} passed to --disassembler is not known.".format(
          args.disassembler))

  finally:
    shutil.rmtree(workspace_dir)

  return ret


if "__main__" == __name__:
  exit(main())
