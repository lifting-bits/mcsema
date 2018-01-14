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

set(MCSEMA_SOURCE_DIR "${PROJECT_SOURCE_DIR}")

# warnings and compiler settings
set(PROJECT_CXXWARNINGS "-Wall -Wextra -Werror -Wconversion -pedantic -Wno-unused-parameter -Wno-c++98-compat -Wno-unreachable-code-return -Wno-nested-anon-types -Wno-extended-offsetof -Wno-gnu-anonymous-struct -Wno-gnu-designator -Wno-variadic-macros -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-statement-expression -Wno-return-type-c-linkage -Wno-c99-extensions -Wno-ignored-attributes -Wno-unused-local-typedef")

set(PROJECT_CXXFLAGS "${PROJECT_CXXFLAGS} -Wno-unknown-warning-option ${PROJECT_CXXWARNINGS} -fPIC -fno-omit-frame-pointer -fvisibility-inlines-hidden -fno-exceptions -fno-asynchronous-unwind-tables -fno-rtti")

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
add_custom_target(protobuf_python_module_ida   DEPENDS ${PROJECT_PROTOBUFPYTHONMODULE})
add_custom_target(protobuf_python_module_binja DEPENDS ${PROJECT_PROTOBUFPYTHONMODULE})

# disable -Werror on these file since they have been generated
set_source_files_properties(${PROJECT_PROTOBUFSOURCEFILES} PROPERTIES COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32 -Wno-conversion")
set_source_files_properties(${PROJECT_PROTOBUFHEADERFILES} PROPERTIES COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32 -Wno-conversion")

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
    TARGET protobuf_python_module_ida PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_PROTOBUFPYTHONMODULE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/mcsema_disass/ida)

add_custom_command(
    TARGET protobuf_python_module_binja PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_PROTOBUFPYTHONMODULE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/mcsema_disass/binja)

# this is needed for the #include directives with absolutes paths to work correctly; it must
# also be set to PUBLIC since mcsema-lift includes some files directly
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR})

add_dependencies(${MCSEMA_LIFT} semantics
                                protobuf_python_module_ida
                                protobuf_python_module_binja)

target_link_libraries(${MCSEMA_LIFT} PRIVATE remill ${PROJECT_LIBRARIES})
target_include_directories(${MCSEMA_LIFT} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${MCSEMA_LIFT} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${MCSEMA_LIFT} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

if ("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/mcsema/Arch/X86/Runtime)
endif()

install(
  TARGETS ${MCSEMA_LIFT}
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib)

install(CODE
    "execute_process(COMMAND python ${PROJECT_SOURCE_DIR}/tools/setup.py install -f --prefix=${CMAKE_INSTALL_PREFIX})")

add_subdirectory(examples)
    