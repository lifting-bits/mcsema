# Copyright (c) 2018 Trail of Bits, Inc.
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

cmake_minimum_required(VERSION 3.2)
project(linux_abi)

function(add_runtime_helper target_name source_file address_bit_size)
  message(" > Generating Linux ABI target: ${target_name}")

  # Visual C++ requires C++14
  if(WIN32)
    set(required_cpp_standard "c++14")
  else()
    set(required_cpp_standard "c++11")
  endif()

  if(DEFINED WIN32)
    set(install_folder "${CMAKE_INSTALL_PREFIX}/mcsema/${REMILL_LLVM_VERSION}/ABI/linux")
  else()
    set(install_folder "${CMAKE_INSTALL_PREFIX}/share/mcsema/${REMILL_LLVM_VERSION}/ABI/linux")
  endif()

  if("${source_file}" MATCHES "\.c$")
    set(bc_build_flags "-xc" "-m${address_bit_size}" "-std=gnu11" "-Wno-deprecated-declarations")
  elseif("${source_file}" MATCHES "\.cpp$")
    set(bc_build_flags "-xc++" "-m${address_bit_size}" "-std=gnu++14" "-Wno-deprecated-declarations")
  else()
    # assume defaults work
    message(WARNING " > WARNING: Unknown file extension for ${source_file}")
    set(bc_build_flags "")
  endif()

  message("Build flags: ${bc_build_flags}")
  add_runtime(${target_name}
    SOURCES ${source_file}
    ADDRESS_SIZE ${address_bit_size}
    BCFLAGS ${bc_build_flags}
    INCLUDEDIRECTORIES "${CMAKE_SOURCE_DIR}"
    INSTALLDESTINATION "${install_folder}"
    DEPENDENCIES ${ARGN}
  )
endfunction()

add_runtime_helper(ABI_exceptions_x86 "ABI_exceptions.cpp" 32)
add_runtime_helper(ABI_libc_x86 "ABI_libc.c" 32 "ABI_libc.h")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_runtime_helper(ABI_exceptions_amd64 "ABI_exceptions.cpp" 64)
  add_runtime_helper(ABI_libc_amd64 "ABI_libc.c" 64 "ABI_libc.h")
endif()
