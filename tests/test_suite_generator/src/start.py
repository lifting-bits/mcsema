#!/usr/bin/env python2

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

import sys
import os
import exceptions
import subprocess
import tempfile
import time

from distutils import spawn

class Test(object):
  def __init__(self, root_path, test_name, platform, architecture):
    self._root_path = root_path
    self._name = test_name
    self._platform = platform
    self._architecture = architecture

    self._cfg_path = os.path.join(self._root_path, "cfg", self._name)
    if not os.path.isfile(self._cfg_path):
      raise IOError("The CFG file does not exists")

    self._bitcode_path = os.path.join(self._root_path, "bc", self._name)
    if not os.path.isfile(self._bitcode_path):
      raise IOError("The bitcode file does not exists")

    self._binary_path = os.path.join(self._root_path, "bin", self._name)
    if not os.path.isfile(self._binary_path):
      raise IOError("The binary file does not exists")

    stdout_path = os.path.join(self._root_path, "stdout", self._name)
    if not os.path.isfile(stdout_path):
      raise IOError("The stdout file does not exists")

    description_file_path = os.path.join(self._root_path, "docs", self._name)
    if not os.path.isfile(description_file_path):
      raise IOError("The documentation file does not exists")

    cppflags_file_path = os.path.join(self._root_path, "cppflags", self._name)
    if not os.path.isfile(cppflags_file_path):
      raise IOError("The CPP linker flags file does not exists")

    linkerflags_file_path = os.path.join(self._root_path, "linkerflags", self._name)
    if not os.path.isfile(linkerflags_file_path):
      raise IOError("The linker flags file does not exists")

    f = open(description_file_path, "r")
    self._description = f.readlines()
    f.close()

    f = open(stdout_path, "r")
    self._output = f.read()
    f.close()

    f = open(linkerflags_file_path, "r")
    self._linker_flags = f.read().replace(";", " ").split(" ")
    f.close()

    f = open(cppflags_file_path, "r")
    self._cpp_flags = f.read().replace(";", " ").split(" ")
    f.close()
  
    input_file_path = os.path.join(self._root_path, "input", self._name)
    if os.path.isfile(input_file_path):
      input_file = open(input_file_path, "r")
      self._input = input_file.readlines()
      input_file.close()
    else:
      self._input = None

  def name(self):
    return self._name

  def cfg_path(self):
    return self._cfg_path

  def binary_path(self):
    return self._binary_path

  def bitcode_path(self):
    return self._bitcode_path

  def description(self):
    return self._description

  def platform(self):
    return self._platform

  def architecture(self):
    return self._architecture

  def input(self):
    return self._input

  def output(self):
    return self._output

  def cpp_flags(self):
    return self._cpp_flags

  def linker_flags(self):
    return self._linker_flags

  def compare_output(self, actual):
    """
    Compare actual to expected output. 
    This function has a looser definition that strict equality (frequency count)
    to work with multithreaded applications that may output in different order
    on every execution.
    """
    expected = self.output()

    # First check: exact output match. 
    if actual == expected:
      return True

    # do frequency count of every character in the string
    def freq_count(string):
      freq_table = {}
      for c in string:
        freq = freq_table.get(c, 0)
        freq += 1
        freq_table[c] = freq

      return freq_table

    return freq_count(actual) == freq_count(expected)

def main():
  toolset = acquire_toolset()
  if toolset is None:
    print("The required toolset could not be found!")
    return False

  test_list = get_test_list()
  if test_list is None:
    print("No tests found!")
    return False

  return execute_tests(toolset, test_list)

def acquire_toolset():
  toolset = {}

  print("Checking the environment...\n")
  if os.environ.get("TRAILOFBITS_LIBRARIES") is None:
    print("The TRAILOFBITS_LIBRARIES variable is not defined!")
    return None

  tob_lib_repository = os.environ["TRAILOFBITS_LIBRARIES"]
  if not os.path.isdir(tob_lib_repository):
    print("The TRAILOFBITS_LIBRARIES has been set to an invalid path!")
    return None

  print(" > Using TRAILOFBITS_LIBRARIES")
  print("   ---")
  print("   " + tob_lib_repository)
  print("")

  print("Acquiring the toolset...\n")
  toolset["clang"] = os.path.join(tob_lib_repository, "llvm", "bin", "clang")
  if sys.platform == "win32":
    toolset["clang"] += ".exe"

  toolset["clang++"] = os.path.join(tob_lib_repository, "llvm", "bin", "clang++")
  if sys.platform == "win32":
    toolset["clang++"] += ".exe"

  toolset["llvm-link"] = os.path.join(tob_lib_repository, "llvm", "bin", "llvm-link")
  if sys.platform == "win32":
    toolset["llvm-link"] += ".exe"

  toolset["llvm-dis"] = os.path.join(tob_lib_repository, "llvm", "bin", "llvm-dis")
  if sys.platform == "win32":
    toolset["llvm-dis"] += ".exe"

  llvm_version = subprocess.check_output([toolset["clang"], "--version"]).split(" ")[2].split("-")[0]
  print(" i Found LLVM version: " + llvm_version)
  print("   in: {}".format(os.path.dirname(toolset["clang"])))

  mcsema_llvm_version = llvm_version.rsplit('.', 1)[0]
  print(" i Using the following mcsema tools: " + mcsema_llvm_version)

  toolset["mcsema-lift"] = spawn.find_executable("mcsema-lift-" + mcsema_llvm_version)
  if toolset["mcsema-lift"] is None:
    print(" x Failed to locate mcsema-lift-" + mcsema_llvm_version)
    return None
  else:
    print(" i Found mcsema-lift in: {}".format(toolset["mcsema-lift"]))

  mcsema_root = os.path.realpath(os.path.join(
    os.path.dirname(toolset["mcsema-lift"]), ".."))

  toolset["mcsema-disass"] = os.path.join(
    mcsema_root, "bin", "mcsema-disass")

  if toolset["mcsema-disass"] is None:
    print(" x Failed to locate mcsema-disass")
    return None
  else:
    print(" i Found mcsema-disass in: {}".format(toolset["mcsema-disass"]))

  if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    lib_suffix = ".a"
  else:
    # assumes this must be Windows
    lib_suffix = ".lib"

  rt_32 = "libmcsema_rt32-" + mcsema_llvm_version + lib_suffix
  rt_64 = "libmcsema_rt64-" + mcsema_llvm_version + lib_suffix
  toolset["libmcsema_rt32"] = os.path.join(mcsema_root, "lib", rt_32)
  toolset["libmcsema_rt64"] = os.path.join(mcsema_root, "lib", rt_64)

  if not os.path.isfile(toolset["libmcsema_rt32"]):
    print(" x Failed to locate the 32-bit mcsema runtime: " + rt_32)
    return None

  if not os.path.isfile(toolset["libmcsema_rt64"]):
    print(" x Failed to locate the 64-bit mcsema runtime" + rt_64)
    return None

  #TODO(artem): support other architectures
  #TODO(artem): support OSes other than Linux
  for arch in ("x86", "amd64"):
    #TODO(artem): support other abi libraries
    for abi in ("exceptions", "libc"):
      ts_name = "abi_library_{abi}_{arch}".format(abi=abi, arch=arch)
      toolset[ts_name] = os.path.join(
        mcsema_root,
        "share",
        "mcsema",
        mcsema_llvm_version,
        "ABI",
        "linux",
        "ABI_{abi}_{arch}.bc".format(abi=abi, arch=arch))

      if not os.path.isfile(toolset[ts_name]):
        print(" x Failed to locate ABI: {name} [looked in: {pth}]".format(name=ts_name, pth=toolset[ts_name]))
        return None

  print(" > Toolset")
  for tool_name, tool_path in toolset.iteritems():
    if not os.path.isfile(tool_path):
      print("The following tool could not be found: " + tool_name + "(" + tool_path + ")")
      return None

    print("    > " + tool_name + ": " + tool_path)

  print("")
  return toolset

def execute_tests(toolset, test_list):
  print("Starting...\n")

  test_directory = tempfile.mkdtemp(
      prefix="mcsema_test_",
      dir=os.path.dirname(os.path.realpath(__file__)))
  print(" > Saving results to: " + test_directory)

  failed_test_list = {}

  for test in test_list:
    print(" > Test name: " + test.name())
    print("   Platform: " + test.platform() + "/" + test.architecture())

    print("   Custom input:"),
    if test.input() is None:
      print("No")
    else:
      print("Yes")

    if test.cpp_flags():
      print("   CXX flags: " + str(test.cpp_flags()))
    else:
      print("   CXX flags: N/A")

    if test.linker_flags():
      print("   Linker flags: " + str(test.linker_flags()))
    else:
      print("   Linker flags: N/A")

    print("")

    for desc_line in test.description():
      desc_line = desc_line.strip()
      if desc_line:
        print("   " + desc_line)
    
    print("\n   Testing...")
    result = lift_test_cfg(test_directory, toolset, test)
    if result["success"]:
      print("    +"),
    else:
      print("    x"),

    print("Lifting")
    if not result["success"]:
      failed_test_list[test.name()] = result["output"]
      print("    ! Test failed\n")
      continue
  
    if test.architecture() != "amd64":
      print("    ! Recompilation not supported for this architecture\n")
      continue

    bitcode_path = result["bitcode_path"]
    result = compile_lifted_code(test_directory, toolset, test, bitcode_path)
    if result["success"]:
      print("    +"),
    else:
      print("    x"),

    print("Recompilation")
    if not result["success"]:
      failed_test_list[test.name() + " (" + test.platform() + "/" + test.architecture() + ")"] = result["output"]
      print("    ! Test failed\n")
      continue

    recompiled_exe_path = result["recompiled_exe_path"]
    result = execute_compiled_bitcode(test_directory, toolset, test, recompiled_exe_path)
    if result["success"]:
      print("    +"),
    else:
      print("    x"),

    print("Execution")
    if not result["success"]:
      failed_test_list[test.name() + " (" + test.platform() + "/" + test.architecture() + ")"] = result["output"]
      print("    ! Test failed\n")
      print("    ! Exe file: {}".format(recompiled_exe_path))
      continue

    print("    i Test passed\n")

  print("Summary\n")
  if len(failed_test_list) == 0:
    print(" i All tests have succeeded")
    return True

  print("   The following tests have failed:")
  for test_name, output in failed_test_list.iteritems():
    print("    > " + test_name)
    print("      ---")

    for output_line in output.split("\n"):
      print("      " + output_line)
  
    print("")

  return False

def lift_test_cfg(test_directory, toolset, test):
  output_file_path = os.path.join(test_directory, test.name() + "_" + test.architecture() + "_" + test.platform() + ".bc")

  # Reference docs/CommandLineReference.md
  # In stripped ELFs, the libc_constructor/libc_destructor functions are init/fini
  exception_library = toolset["abi_library_exceptions_{arch}".format(arch=test.architecture())]
  libc_library = toolset["abi_library_libc_{arch}".format(arch=test.architecture())]
  abi_libs = ",".join([exception_library, libc_library])

  command_line = [toolset["mcsema-lift"],
                  "--arch", test.architecture(),
                  "--os", test.platform(), "--cfg", test.cfg_path(),
                  "--output", output_file_path,
                  "--explicit_args",
                  "--local_state_pointer",
                  "--libc_constructor", "init",
                  "--libc_destructor", "fini", 
                  "--abi_libraries", abi_libs,
                  ]

  exec_result = execute_with_timeout(command_line, 1200)

  result = {}
  result["output"] = "Exit code: " + exec_result["exit_code"] + "\nstdout:\n"  + exec_result["stdout"] + "\n\nstderr:\n" + exec_result["stderr"]

  if not exec_result["success"]:
    result["success"] = False
    result["bitcode_path"] = None
  else:
    result["success"] = True
    result["bitcode_path"] = output_file_path

  return result

def compile_lifted_code(test_directory, toolset, test, bitcode_path):
  if test.architecture() != "amd64":
    result = {}
    result["success"] = False
    result["output"] = "Not yet supported"
    return result

  output_file_path = os.path.join(test_directory, test.name())

  if test.architecture() == "amd64" or test.architecture() == "aarch64":
    mcsema_runtime_path = toolset["libmcsema_rt64"]
  else:
    mcsema_runtime_path = toolset["libmcsema_rt32"]

  command_line = [toolset["clang++"], "-rdynamic", "-o", output_file_path, bitcode_path, mcsema_runtime_path, "-Wno-unknown-warning-option", "-Wno-override-module"]
  if len(test.cpp_flags()) != 0:
    command_line += test.cpp_flags()

  if len(test.linker_flags()) != 0:
    command_line += test.linker_flags()

  if test.architecture() == "amd64" or test.architecture() == "aarch64":
    command_line.append("-m64")
  else:
    command_line.append("-m32")

  exec_result = execute_with_timeout(command_line, 60)

  result = {}

  command_line_description = "Command line:\n"
  for s in command_line:
    command_line_description += s + " "
  command_line_description += "\n"

  result["output"] = command_line_description + "Exit code: " + exec_result["exit_code"] + "\nstdout:\n"  + exec_result["stdout"] + "\n\nstderr:\n" + exec_result["stderr"]

  if not exec_result["success"]:
    result["success"] = False
    result["recompiled_exe_path"] = None
  else:
    result["success"] = True
    result["recompiled_exe_path"] = output_file_path

  return result

def execute_compiled_bitcode(test_directory, toolset, test, recompiled_exe_path):
  output_file_path = os.path.join(test_directory, test.name() + "_" + test.architecture() + "_" + test.platform() + "_stdout_test")

  output = ""
  if test.input() is None:
    exec_result = execute_with_timeout([recompiled_exe_path], 60)
    if not exec_result["success"]:
      result = {}
      result["output"] = "Exit code: " + exec_result["exit_code"] + "\nstdout:\n"  + exec_result["stdout"] + "\n\nstderr:\n" + exec_result["stderr"]
      result["success"] = False

      return result

    output = exec_result["stdout"] + exec_result["stderr"]

  else:
    for input_line in test.input():
      exec_result = execute_with_timeout([recompiled_exe_path, input_line], 60)
      if not exec_result["success"]:
        result = {}
        result["output"] = "Input: " + input_line + "\nExit code: " + exec_result["exit_code"] + "\nstdout:\n"  + exec_result["stdout"] + "\n\nstderr:\n" + exec_result["stderr"]
        result["success"] = False

        return result

      output += exec_result["stdout"] + exec_result["stderr"]

  result = {}
  result["success"] = test.compare_output(output)
  if not result["success"]:
    result["output"] = "Output:\n" + output + "\n\nExpected:\n" + test.output()
  else:
    result["output"] = ""

  return result

def execute_with_timeout(args, timeout):
  result = {}

  print("   > Executing: " + " ".join(args))
  program_stdout = tempfile.NamedTemporaryFile()
  program_stderr = tempfile.NamedTemporaryFile()

  process = subprocess.Popen(args, stderr=program_stderr, stdout=program_stdout)
  seconds_elapsed = 0

  while process.poll() is None and seconds_elapsed <= timeout:
    time.sleep(1)
    seconds_elapsed += 1

  result = {}
  result["exit_code"] = str(process.returncode)

  program_stdout.seek(0)
  result["stdout"] = program_stdout.read()

  program_stderr.seek(0)
  result["stderr"] = program_stderr.read()

  program_stderr.close()
  program_stdout.close()

  if seconds_elapsed > timeout or process.returncode is None:
    result["success"] = False
    result["stdout"] = "The program execution has timed out (interrupted after " + str(seconds_elapsed) + " seconds)\n" + result["stdout"]
    return result

  if process.returncode != 0:
    result["success"] = False
    result["stdout"] = "The program exited with a value that is not zero: " + str(process.returncode) + "\n" + result["stdout"]
    return result

  result["success"] = True
  return result

def get_test_list():
  test_suite_location = os.path.dirname(os.path.realpath(__file__))

  architecture_list = ["x86", "amd64", "aarch64"]
  platform_list = ["linux", "windows", "macos"]
  test_list = []

  print("Enumerating tests...\n")
  for architecture in architecture_list:
    for platform in platform_list:
      platform_path = os.path.join(test_suite_location, architecture, platform)
      if not os.path.isdir(platform_path):
        continue

      test_name_list = list_files(os.path.join(platform_path, "bin"))
      if test_name_list is None:
        print("Skipping: " + architecture + "/" + platform)
        continue

      for test_name in test_name_list:
        try:
          test_object = Test(platform_path, test_name, platform, architecture)
          test_list.append(test_object)

          print(" > " + test_object.name() + " (" + test_object.platform() + "/" + test_object.architecture() + ")")

        except Exception as e:
          print(" x " + test_name)
          print("   ---")
          print("   Skipped due to the following error:")
          print("   " + str(e) + "\n")

  print("")
  return test_list

def list_files(path):
  file_list = []

  for file_name in os.listdir(path):
    absolute_file_path = os.path.join(path, file_name)
    if os.path.isdir(absolute_file_path):
      continue

    file_list.append(file_name)

  if len(file_list) == 0:
    return None

  return file_list

if __name__ == "__main__":
  if not main():
    sys.exit(1)

  sys.exit(0)
