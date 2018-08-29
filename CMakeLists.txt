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

project(mcsema)
cmake_minimum_required(VERSION 3.2)

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/settings.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils.cmake")

FindAndSelectClangCompiler()

set(MCSEMA_SOURCE_DIR "${PROJECT_SOURCE_DIR}")

# warnings and compiler settings
if(NOT DEFINED WIN32)
  set(PROJECT_CXXFLAGS
    ${GLOBAL_CXXFLAGS} -Werror -Wconversion -pedantic 
    -Wno-unreachable-code-return 
  )
endif()

# protobuf
find_package(Protobuf REQUIRED)
list(APPEND PROJECT_LIBRARIES ${Protobuf_LIBRARIES})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${Protobuf_INCLUDE_DIR})
list(APPEND PROJECT_DEFINITIONS "GOOGLE_PROTOBUF_NO_RTTI")

#
# protobuf file generation
#

# this function can't be told where to store the output files! we have to add the whole binary directory
# to the include directories (or change it and lose compatibility with the system libraries)
protobuf_generate_cpp(PROJECT_PROTOBUFSOURCEFILES
  PROJECT_PROTOBUFHEADERFILES "${CMAKE_CURRENT_SOURCE_DIR}/mcsema/CFG/CFG.proto"
)

list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_CURRENT_BINARY_DIR})

protobuf_generate_python(PROJECT_PROTOBUFPYTHONMODULE
  "${CMAKE_CURRENT_SOURCE_DIR}/mcsema/CFG/CFG.proto"
)

add_custom_target(protobuf_python_module_ida
  DEPENDS ${PROJECT_PROTOBUFPYTHONMODULE}
)

add_custom_target(protobuf_python_module_binja
  DEPENDS ${PROJECT_PROTOBUFPYTHONMODULE}
)

# disable -Werror on these file since they have been generated
set_source_files_properties(${PROJECT_PROTOBUFSOURCEFILES} PROPERTIES
  COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32 -Wno-conversion"
)

set_source_files_properties(${PROJECT_PROTOBUFHEADERFILES} PROPERTIES
  COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32 -Wno-conversion"
)

#
# target settings
#

set(MCSEMA_LIFT mcsema-lift-${REMILL_LLVM_VERSION})

add_executable(${MCSEMA_LIFT}
  ${PROJECT_PROTOBUFSOURCEFILES}

  mcsema/Arch/ABI.cpp
  mcsema/Arch/Arch.cpp

  mcsema/CFG/CFG.cpp

  mcsema/BC/Callback.cpp
  mcsema/BC/External.cpp
  mcsema/BC/Function.cpp
  mcsema/BC/Instruction.cpp
  mcsema/BC/Legacy.cpp
  mcsema/BC/Lift.cpp
  mcsema/BC/Optimize.cpp
  mcsema/BC/Segment.cpp
  mcsema/BC/Util.cpp

  tools/mcsema_lift/Lift.cpp
)

# Copy mcsema-disass in
add_custom_command(
  TARGET protobuf_python_module_ida POST_BUILD
  DEPENDS {PROJECT_PROTOBUFPYTHONMODULE}
  COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_PROTOBUFPYTHONMODULE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/mcsema_disass/ida
)

add_custom_command(
  TARGET protobuf_python_module_binja POST_BUILD
  DEPENDS {PROJECT_PROTOBUFPYTHONMODULE}
  COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_PROTOBUFPYTHONMODULE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/mcsema_disass/binja
)

# this is needed for the #include directives with absolutes paths to work correctly; it must
# also be set to PUBLIC since mcsema-lift includes some files directly
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR})

add_dependencies(${MCSEMA_LIFT}
  semantics protobuf_python_module_ida
  protobuf_python_module_binja
)

#
# libraries
#

# remill
if(NOT TARGET remill)
  if("${PLATFORM_NAME}" STREQUAL "windows")
    set(REMILL_FINDPACKAGE_HINTS HINTS "${CMAKE_INSTALL_PREFIX}/remill/lib")
  endif()

  find_package(remill REQUIRED ${REMILL_FINDPACKAGE_HINTS})
endif()

list(APPEND PROJECT_LIBRARIES remill)

# llvm
find_package(LLVM REQUIRED CONFIG HINTS ${FINDPACKAGE_LLVM_HINTS})

string(REPLACE "." ";" LLVM_VERSION_LIST ${LLVM_PACKAGE_VERSION})
list(GET LLVM_VERSION_LIST 0 LLVM_MAJOR_VERSION)
list(GET LLVM_VERSION_LIST 1 LLVM_MINOR_VERSION)

set(LLVM_LIBRARIES
  LLVMCore LLVMSupport LLVMAnalysis LLVMipo LLVMIRReader
  LLVMBitReader LLVMBitWriter LLVMTransformUtils LLVMScalarOpts
  LLVMLTO
)

list(APPEND PROJECT_LIBRARIES ${LLVM_LIBRARIES})
list(APPEND PROJECT_DEFINITIONS ${LLVM_DEFINITIONS})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${LLVM_INCLUDE_DIRS})

# xed
find_package(XED REQUIRED)
list(APPEND PROJECT_LIBRARIES ${XED_LIBRARIES})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${XED_INCLUDE_DIRS})

# google log module
find_package(glog REQUIRED)
list(APPEND PROJECT_LIBRARIES glog::glog)

# gflags
find_package(gflags REQUIRED)
list(APPEND PROJECT_LIBRARIES gflags)

#
# target settings
#

target_link_libraries(${MCSEMA_LIFT} PRIVATE ${PROJECT_LIBRARIES})
target_include_directories(${MCSEMA_LIFT} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${MCSEMA_LIFT} PUBLIC ${PROJECT_DEFINITIONS})
target_compile_options(${MCSEMA_LIFT} PRIVATE ${PROJECT_CXXFLAGS})

if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/mcsema/Arch/X86/Runtime)
endif()

#TODO(artem): this may need some logic to select only ABIs compatible with current os/arch
#TODO(kumarak): Disable the ABI libraries build till we don't have script to automate the generation of `ABI_libc.h`. Use pre-build library to test the --abi_libraries flag
if(UNIX AND NOT APPLE)
  add_subdirectory(mcsema/OS/Linux)
endif()

if(DEFINED WIN32)
  set(install_folder "${CMAKE_INSTALL_PREFIX}/mcsema")
else()
  set(install_folder "${CMAKE_INSTALL_PREFIX}")
endif()

install(
  TARGETS ${MCSEMA_LIFT}
  RUNTIME DESTINATION "${install_folder}/bin"
  LIBRARY DESTINATION "${install_folder}/lib"
)

set(python_package_installer "${CMAKE_CURRENT_SOURCE_DIR}/tools/setup_launcher")

if(DEFINED WIN32)
  string(REPLACE "/" "\\" python_package_install_path "${install_folder}")
  set(python_package_installer "${python_package_installer}.bat")
else()
  set(python_package_install_path "${install_folder}")
  set(python_package_installer "${python_package_installer}.sh")
endif()

install(CODE
  "execute_process(COMMAND \"${python_package_installer}\" \"${python_package_install_path}\" WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tools RESULT_VARIABLE exit_code)
   if(NOT exit_code EQUAL 0)
     message(FATAL_ERROR \"Failed to install the Python package\")
   endif()"
)

add_subdirectory(examples)

