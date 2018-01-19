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

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import tempfile

def binary_info(binary):
  res = subprocess.check_output(['file', binary])
  is_pie = 'LSB shared object' in res
  address_size = 64

  if 'aarch64' in res:
    arch = 'aarch64'
  elif 'x86-64' in res:
    arch = 'amd64_avx'
  elif 'x86' in res:
    arch = 'x86_avx'
    address_size = 32
  else:
    raise Exception("Unknown architecture for file type {}".format(res))

  return address_size, arch, is_pie

def binary_libraries(binary):
  try:
    res = subprocess.check_output(['ldd', binary])
  except:
    return
  for line in res.split("\n"):
    if "=>" not in line:
      continue
    name, path_and_addr = line.split(" => ")
    path_and_addr = path_and_addr.strip(" ")
    if not path_and_addr.startswith("/"):
      continue
    
    lib = " ".join(path_and_addr.split(" ")[:-1])
    lib = os.path.realpath(lib)

    if os.path.isfile(lib):
      yield name.strip(), lib

def make_executable(path):
  st = os.stat(path)
  os.chmod(path, st.st_mode | stat.S_IEXEC)

def hash_file(path):
  hash = hashlib.md5()
  with open(path, "rb") as f:
    for block in iter(lambda: f.read(65536), b""):
      hash.update(block)
  return hash.hexdigest()

def make_directory(path):
  try:
    os.makedirs(path)
  except:
    pass

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
      '--ida_dir',
      help='Directory containing IDA binaries.',
      required=True)

  arg_parser.add_argument(
      '--workspace_dir',
      help='Directory in which intermediate and final files are placed',
      required=True)

  arg_parser.add_argument(
      '--binary',
      help='Path to the binary to be lifted',
      required=True)

  arg_parser.add_argument(
      '--dry_run',
      help='Should the actual commands be executed?',
      default=False,
      required=False)

  arg_parser.add_argument(
      '--legacy_mode',
      help='Are we producing legacy mode bitcode?',
      default=False,
      required=False,
      action='store_true')

  args, command_args = arg_parser.parse_known_args()

  # Set up the workspace.
  args.workspace_dir = os.path.realpath(args.workspace_dir)
  bin_dir = os.path.join(args.workspace_dir, 'bin')
  lib_dir = os.path.join(args.workspace_dir, 'lib')
  obj_dir = os.path.join(args.workspace_dir, 'obj')
  lifted_obj_dir = os.path.join(args.workspace_dir, 'lifted_obj')
  cfg_dir = os.path.join(args.workspace_dir, 'cfg')
  bc_dir = os.path.join(args.workspace_dir, 'bc')
  log_dir = os.path.join(args.workspace_dir, 'log')

  print "mkdir -p {}".format(args.workspace_dir)
  print "mkdir -p {}".format(bin_dir)
  print "mkdir -p {}".format(lifted_obj_dir)
  print "mkdir -p {}".format(lib_dir)
  print "mkdir -p {}".format(obj_dir)
  print "mkdir -p {}".format(cfg_dir)
  print "mkdir -p {}".format(bc_dir)
  print "mkdir -p {}".format(log_dir)

  make_directory(args.workspace_dir)
  make_directory(bin_dir)
  make_directory(bin_dir)
  make_directory(lifted_obj_dir)
  make_directory(lib_dir)
  make_directory(obj_dir)
  make_directory(cfg_dir)
  make_directory(bc_dir)
  make_directory(log_dir)

  path = os.path.realpath(args.binary)
  path_hash = hash_file(path)

  binary = os.path.join(obj_dir, path_hash)
  lifted_binary = os.path.join(lifted_obj_dir, path_hash)
  cfg = os.path.join(cfg_dir, "{}.cfg".format(path_hash))
  bitcode = os.path.join(bc_dir, "{}.bc".format(path_hash))
  log = os.path.join(log_dir, "{}.log".format(path_hash))

  # Copy the binary into the workspace's object directory.
  print "cp {} {}".format(path, binary)
  print "chmod a+x {}".format(binary)
  if not os.path.isfile(binary):
    shutil.copyfile(args.binary, binary)
    make_executable(binary)
  
  # Copy the shared libraries into the workspace's object directory, and then
  # add symbolic links from the workspace's library directory into the object
  # directory.
  libs = []
  for name, path in binary_libraries(binary):
    path_hash = hash_file(path)
    library = os.path.join(obj_dir, "{}.so".format(path_hash))
    
    if not os.path.isfile(library):
      shutil.copyfile(path, library)
      make_executable(library)

    sym_name = os.path.join(lib_dir, name)
    if os.path.exists(sym_name):
      os.remove(sym_name)

    try:
      os.symlink(library, sym_name)
    except:
      pass

    print "cp {} {}".format(path, library)
    print "chmod a+x {}".format(library)
    print "rm {}".format(sym_name)
    print "ln {} {}".format(library, sym_name)

    libs.append(sym_name)

  os_name = 'linux'
  binary_name = os.path.basename(args.binary)
  address_size, arch, is_pie = binary_info(binary)

  ida_version = {
    "x86_avx": "idal",
    "amd64_avx": "idal64",
    "aarch64": "idal64"
  }[arch]

  # Disassemble the binary.
  ida_args = [
      'mcsema-disass',
      '--arch', arch,
      '--os', os_name,
      '--binary', binary,
      '--output', cfg,
      '--entrypoint', 'main',
      '--disassembler', os.path.join(args.ida_dir, ida_version),
      '--log_file', log,
      is_pie and '--pie-mode' or '']

  ida_args.extend(command_args)

  print " ".join(ida_args)
  ret = subprocess.call(ida_args)
  if ret:
    return ret

  # Lift the binary.
  mcsema_lift_args = [
      'mcsema-lift-{}'.format(args.llvm_version),
      '--arch', arch,
      '--os', os_name,
      '--cfg', cfg,
      '--output', bitcode]

  if args.legacy_mode:
    mcsema_lift_args.append('--legacy_mode')

  print " ".join(mcsema_lift_args)
  ret = subprocess.call(mcsema_lift_args)
  if ret:
    return ret
  
  # Not compiling a binary.
  if args.legacy_mode:
    return 0

  # Build up the command-line invocation to clang.
  clang_args = [
      os.path.join(args.libraries_dir, 'llvm', 'bin', 'clang++'),
      '-rdynamic',
      is_pie and '-fPIC' or '',
      is_pie and '-pie' or '',
      '-o', lifted_binary,
      bitcode,
      '/usr/local/lib/libmcsema_rt{}-{}.a'.format(
          address_size, args.llvm_version),
      '-lm']

  for lib in libs:
    clang_args.append(lib)

  # Compile back to an executable.
  print " ".join(clang_args)
  ret = subprocess.call(clang_args)
  if ret:
    return ret

  # Create two scripts to run the original and native.
  run_native = os.path.join(bin_dir, binary_name)
  with open(run_native, "w") as f:
    f.write("""#!/usr/bin/env bash
LD_LIBRARY_PATH={} {} "$@"
""".format(lib_dir, binary))

  run_lifted = os.path.join(bin_dir, "{}.lifted".format(binary_name))
  with open(run_lifted, "w") as f:
    f.write("""#!/usr/bin/env bash
LD_LIBRARY_PATH={} {} "$@"
""".format(lib_dir, lifted_binary))

  make_executable(run_native)
  make_executable(run_lifted)

  return 0

if __name__ == "__main__":
  exit(main())