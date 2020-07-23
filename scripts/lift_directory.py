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
import multiprocessing
import os
import shutil
import stat
import subprocess

def is_ELF_file(path):
  try:
    output = subprocess.check_output(['file', path])
    return 'ELF' in output
  except:
    return False

def lift_binary(args, binary):
  lift_args = [
      'python',
      os.path.join(os.path.dirname(__file__), 'lift_program.py'),
      '--libraries_dir', args.libraries_dir,
      '--llvm_version', args.llvm_version,
      '--disassembler', args.disassembler,
      '--workspace_dir', args.workspace_dir,
      '--binary', binary]

  if args.extra_args != "":
    for arg in args.extra_args.split(','):
      lift_args.append(arg)

  if args.legacy_mode:
    lift_args.append('--legacy_mode')

  binary_name = os.path.basename(binary)
  sub_stdout_path = os.path.join(
      args.workspace_dir, "{}.stdout".format(binary_name))
  sub_stderr_path = os.path.join(
      args.workspace_dir, "{}.stderr".format(binary_name))
  with open(sub_stdout_path, "w") as sub_stdout:
    with open(sub_stderr_path, "w") as sub_stderr:
      print(" ".join(lift_args))
      return subprocess.call(lift_args, stdout=sub_stdout, stderr=sub_stderr)

def main():
  arg_parser = argparse.ArgumentParser()

  arg_parser.add_argument(
      '--libraries_dir',
      help='Path to directory in which the cxx-common libraries are unpacked',
      required=True)

  arg_parser.add_argument(
      '--llvm_version',
      help='Version number MAJOR.MINOR of the LLVM toolchain',
      required=True)

  arg_parser.add_argument(
      '--disassembler',
      help='Path to disassembler, or just "binja", if installed.',
      required=True)

  arg_parser.add_argument(
      '--workspace_dir',
      help='Directory in which intermediate and final files are placed',
      required=True)

  arg_parser.add_argument(
      '--binary_dir',
      help='Path to the directory of binaries to be lifted',
      required=True)

  arg_parser.add_argument(
      '--num_workers',
      help='Number of concurrent workers for the lifting job',
      default=1,
      type=int)

  arg_parser.add_argument(
      '--legacy_mode',
      help='Are we producing legacy mode bitcode?',
      default=False,
      required=False,
      action='store_true')

  arg_parser.add_argument(
      '--extra_args',
      '--list',
      nargs='+',
      help='A space-delimited list of any extra arguments to pass to the lifter.',
      default="",
      required=False)

  args, command_args = arg_parser.parse_known_args()

  binaries = set()

  for name in list(os.listdir(args.binary_dir)):
    binary = os.path.realpath(os.path.join(args.binary_dir, name))
    if not os.path.isfile(binary):
      continue

    st = os.stat(binary)
    if 0 == (stat.S_IEXEC & st.st_mode):
      continue

    if not is_ELF_file(binary):
      continue

    binaries.add(binary)

  ret_codes = {}
  pool = multiprocessing.Pool(args.num_workers)
  #try:
  for binary in binaries:
    ret_codes[binary] = pool.apply_async(lift_binary, (args, binary))

  pool.close()
  pool.join()

  ret = 0
  for binary, ret_code in ret_codes.items():
    if ret_code.get():
      print("Error lifting {}".format(binary))
      ret = 1
  #except:
  #  pool.terminate()

  return ret

if __name__ == "__main__":
  exit(main())