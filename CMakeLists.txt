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
cmake_minimum_required (VERSION 3.2)

#
# compiler selection
#

if (DEFINED ENV{LLVM_INSTALL_PREFIX})
    set(LLVM_INSTALL_PREFIX $ENV{LLVM_INSTALL_PREFIX})
endif ()

# it is important to avoid re-defining these variables if they have been already
# set or you risk ending up in a configure loop!
if (NOT DEFINED CMAKE_C_COMPILER)
    if (DEFINED LLVM_INSTALL_PREFIX)
        set(CMAKE_C_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang")
    else ()
        set(CMAKE_C_COMPILER "clang")
    endif ()
endif ()

if (NOT DEFINED CMAKE_CXX_COMPILER)
    if (DEFINED LLVM_INSTALL_PREFIX)
        set(CMAKE_CXX_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++")
    else ()
        set(CMAKE_CXX_COMPILER "clang++")
    endif ()
endif ()

if (NOT DEFINED CMAKE_ASM_COMPILER)
    if (DEFINED LLVM_INSTALL_PREFIX)
        set(CMAKE_ASM_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang")
    else ()
        set(CMAKE_ASM_COMPILER ${CMAKE_CXX_COMPILER})
    endif ()
endif ()

if (NOT DEFINED CMAKE_LLVM_LINK)
    if (DEFINED LLVM_INSTALL_PREFIX)
        set(CMAKE_LLVM_LINK "${LLVM_INSTALL_PREFIX}/bin/llvm-link")
    else ()
        set(CMAKE_LLVM_LINK "llvm-link")
    endif ()
endif ()

#
# compiler settings
#

# enable the gnu extensions
set(CMAKE_CXX_EXTENSIONS ON)

# visual studio already defaults to c++11
if (NOT WIN32)
    set(CMAKE_CXX_STANDARD 11)
endif ()

# warnings and compiler settings
set(PROJECT_CXXWARNINGS "-Wall -Wextra -Werror -Wconversion -pedantic -Wno-unused-parameter -Wno-c++98-compat -Wno-unreachable-code-return -Wno-nested-anon-types -Wno-extended-offsetof -Wno-gnu-anonymous-struct -Wno-gnu-designator -Wno-variadic-macros -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-statement-expression -Wno-return-type-c-linkage -Wno-c99-extensions -Wno-ignored-attributes -Wno-unused-local-typedef")
set(PROJECT_CXXFLAGS "${PROJECT_CXXFLAGS} -Wno-unknown-warning-option ${PROJECT_CXXWARNINGS} -fPIC -fno-omit-frame-pointer -fvisibility-inlines-hidden -fno-exceptions -fno-asynchronous-unwind-tables -fno-rtti")

# default build type
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif ()

# debug symbols
if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(PROJECT_CXXFLAGS "${PROJECT_CXXFLAGS} -gdwarf-2 -g3")
endif ()

# optimization flags and definitions
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(PROJECT_CXXFLAGS "${PROJECT_CXXFLAGS} -O0")
else ()
    set(PROJECT_CXXFLAGS "${PROJECT_CXXFLAGS} -O3")
    list(APPEND PROJECT_DEFINITIONS "NDEBUG")
endif ()

#
# libraries
#

if (DEFINED ENV{TRAILOFBITS_LIBRARIES})
    set(LIBRARY_REPOSITORY_ROOT $ENV{TRAILOFBITS_LIBRARIES})
    include("${LIBRARY_REPOSITORY_ROOT}/cmake/repository.cmake")

    message(STATUS "Using the following library repository: ${LIBRARY_REPOSITORY_ROOT}")
else ()
    message(STATUS "Using system libraries")
endif ()

if (DEFINED ENV{TRAILOFBITS_LIBRARIES})
    set(LIBRARY_REPOSITORY_ROOT $ENV{TRAILOFBITS_LIBRARIES})
    include("${LIBRARY_REPOSITORY_ROOT}/cmake/repository.cmake")

    message(STATUS "Using the following library repository: ${LIBRARY_REPOSITORY_ROOT}")
else ()
    message(STATUS "Using system libraries")
endif ()

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
protobuf_generate_cpp(PROJECT_PROTOBUFSOURCEFILES PROJECT_PROTOBUFHEADERFILES "${CMAKE_CURRENT_SOURCE_DIR}/mcsema/CFG/CFG.proto")
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_CURRENT_BINARY_DIR})

protobuf_generate_python(PROJECT_PROTOBUFPYTHONMODULE "${CMAKE_CURRENT_SOURCE_DIR}/mcsema/CFG/CFG.proto")
add_custom_target(protobuf_python_module DEPENDS ${PROJECT_PROTOBUFPYTHONMODULE})

# disable -Werror on these file since they have been generated
set_source_files_properties(${PROJECT_PROTOBUFSOURCEFILES} PROPERTIES COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32")
set_source_files_properties(${PROJECT_PROTOBUFHEADERFILES} PROPERTIES COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32")

#
# target settings
#

add_executable(mcsema-lift
    ${PROJECT_PROTOBUFSOURCEFILES}

    mcsema/Arch/Arch.cpp
    mcsema/CFG/CFG.cpp
    mcsema/BC/Callback.cpp
    mcsema/BC/External.cpp
    mcsema/BC/Function.cpp
    mcsema/BC/Instruction.cpp
    mcsema/BC/Lift.cpp
    mcsema/BC/Optimize.cpp
    mcsema/BC/Segment.cpp
    mcsema/BC/Util.cpp

    tools/mcsema_lift/Lift.cpp
)

# Copy mcsema-disass in
add_custom_command(
    TARGET protobuf_python_module PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_PROTOBUFPYTHONMODULE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/mcsema_disass/ida)

# this is needed for the #include directives with absolutes paths to work correctly; it must
# also be set to PUBLIC since remill-lift includes some files directly
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR})

add_dependencies(mcsema-lift semantics protobuf_python_module)

target_link_libraries(mcsema-lift PRIVATE remill ${PROJECT_LIBRARIES})
target_include_directories(mcsema-lift SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(mcsema-lift PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(mcsema-lift PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/mcsema/Arch/X86/Runtime)

install(CODE
    "execute_process(COMMAND python ${PROJECT_SOURCE_DIR}/tools/setup.py install -f --prefix=${CMAKE_INSTALL_PREFIX})")
