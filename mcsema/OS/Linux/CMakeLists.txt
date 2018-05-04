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


if (NOT TARGET remill)
		# Remill's  CMake definitions are required to build to bitcode
    message(FATAL_ERROR "The remill target does not exists!")
endif ()

# Fix behavior of CMAKE_CXX_STANDARD when targeting macOS.
if (POLICY CMP0025)
  cmake_policy(SET CMP0025 NEW)
endif ()

cmake_minimum_required (VERSION 3.2)
project(linux_abi BC)

# Define OS ahead of time so ports to other OSes are easier
set(CURRENT_OS linux)

set(LINUXABI_INCLUDEDIRECTORIES ${CMAKE_SOURCE_DIR})

function (language add_runtime_helper target_name target_arch address_bit_size)
    message(" > Generating ${CURRENT_OS} ABI target: ${target_name}")

		# example name: ABI_libc_x86.bc
		set(full_name ${target_name}_${target_arch})

		# remove this warning as the ABI libraries need to capture deprecated declarations
		set_source_files_properties(${target_name}.${language} PROPERTIES COMPILE_FLAGS "-Wno-deprecated-declarations")
    add_runtime(${full_name} SOURCES ${target_name}.${language} ADDRESS_SIZE ${address_bit_size})

    target_include_directories(${full_name} PRIVATE ${LINUXABI_INCLUDEDIRECTORIES})

    install(TARGETS ${full_name} DESTINATION "share/mcsema/${REMILL_LLVM_VERSION}/ABI/${CURRENT_OS}")

endfunction ()

# X86 ABIs
add_runtime_helper(cpp ABI_exceptions x86 32)
add_runtime_helper(c ABI_libc x86 32)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    # AMD64 ABIs
    add_runtime_helper(cpp ABI_exceptions amd64 64)
    add_runtime_helper(c ABI_libc amd64 64)
endif ()
