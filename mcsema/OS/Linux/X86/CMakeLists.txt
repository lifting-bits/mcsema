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
    set(bc_build_flags "-femit-all-decls" "-xc" "-m${address_bit_size}" "-std=gnu11" "-Wno-deprecated-declarations")
  elseif("${source_file}" MATCHES "\.cpp$")
    set(bc_build_flags "-femit-all-decls" "-xc++" "-m${address_bit_size}" "-std=gnu++14" "-Wno-deprecated-declarations")
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

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libc.c ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libc.h
  DEPENDS ${source_file}
  COMMAND env TRAILOFBITS_LIBRARIES=${CXX_COMMON_REPOSITORY_ROOT} python3 ${CMAKE_CURRENT_SOURCE_DIR}/../generate_abi_wrapper.py
  		--arch "amd64" --type "c" --input ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libc.pph --output ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libc.c 
)

#add_custom_command(
#  OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libc_x86.c ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libc.h
#  DEPENDS ${source_file}
#  COMMAND env TRAILOFBITS_LIBRARIES=${CXX_COMMON_REPOSITORY_ROOT} python3 ${CMAKE_CURRENT_SOURCE_DIR}/../generate_abi_wrapper.py 
#        --arch "x86" --type "c" --input ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libc.pph --output ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libc_x86.c
#)

#add_custom_command(
#  OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libcpp_amd64.c
#  DEPENDS ${source_file}
#  COMMAND env TRAILOFBITS_LIBRARIES=${CXX_COMMON_REPOSITORY_ROOT} python ${CMAKE_CURRENT_SOURCE_DIR}/../generate_abi_wrapper.py 
#  		--arch "amd64" --type "cpp" --input ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libc.pph --output ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libcpp_amd64.c 
#)

#add_custom_command(
#  OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libcpp_x86.c
#  DEPENDS ${source_file}
#  COMMAND env TRAILOFBITS_LIBRARIES=${CXX_COMMON_REPOSITORY_ROOT} python ${CMAKE_CURRENT_SOURCE_DIR}/../generate_abi_wrapper.py 
#        --arch "x86" --type "cpp" --input ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libc.pph --output ${CMAKE_CURRENT_SOURCE_DIR}/ABI_libcpp_x86.c
#)

add_runtime_helper(ABI_exceptions_x86 "ABI_exceptions.cpp" 32)
add_runtime_helper(ABI_libc_x86 "ABI_libc.c" 32 "ABI_libc.h")
#add_runtime_helper(ABI_libcpp_x86 "ABI_libcpp_x86.c" 32 "ABI_libc.h")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_runtime_helper(ABI_exceptions_amd64 "ABI_exceptions.cpp" 64)
  add_runtime_helper(ABI_libc_amd64 "ABI_libc.c" 64 "ABI_libc.h")
#  add_runtime_helper(ABI_libcpp_amd64 "ABI_libcpp_amd64.c" 32 "ABI_libc.h")
endif()
