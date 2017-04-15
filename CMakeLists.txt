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

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/protobuf" "${PROJECT_SOURCE_DIR}/cmake" "${CMAKE_ROOT}/Modules")

if(NOT WIN32)
  #FindPackage for protobuf is terrible for win32
  # it assumes MSVC built protobuf from a visual studio project
  #... we build with custom cmake, so it will never be found
  #... but it should work for other OSes where we install from a package
  set(CMAKE_CXX_STANDARD 11)

  include (${PROJECT_SOURCE_DIR}/cmake/protobuf/CMakeLists.txt)
  set(PROTOBUF_INCLUDE_DIRS "${PROTOBUF_ROOT}/src")
  set(PROTOBUF_LIBRARIES "$<TARGET_FILE:libprotobuf>")
  set(PROTOBUF_PROTOC_EXECUTABLE "$<TARGET_FILE:protoc>")
else()
   # on win32, manuallys set protobuf goodness
   set(PROTOBUF_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}/include")
   set(PROTOBUF_LIBRARIES "${PROJECT_SOURCE_DIR}/lib/protobuf.lib")
   set(PROTOBUF_PROTOC_EXECUTABLE "${PROJECT_SOURCE_DIR}/bin/protoc.exe")
endif()

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROTOBUF_INCLUDE_DIRS})

add_executable(mcsema-lift
  EXCLUDE_FROM_ALL
  generated/CFG.pb.cc
  mcsema/Arch/Arch.cpp
  mcsema/CFG/CFG.cpp
  mcsema/BC/External.cpp
  mcsema/BC/Function.cpp
  mcsema/BC/Instruction.cpp
  mcsema/BC/Lift.cpp
  mcsema/BC/Optimize.cpp
  mcsema/BC/Segment.cpp
  mcsema/BC/Util.cpp
  mcsema/tools/mcsema_lift/Lift.cpp
)

add_dependencies(mcsema-lift
  semantics
)

target_link_libraries(mcsema-lift
  remill
  ${PROTOBUF_LIBRARIES}
)

add_subdirectory(${PROJECT_SOURCE_DIR}/mcsema/Arch/X86/Runtime)

#install(
#  TARGETS mcsema-lift 
#  RUNTIME DESTINATION bin
#  LIBRARY DESTINATION lib)
