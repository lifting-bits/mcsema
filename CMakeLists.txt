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

project(MCSEMA)

# protobuf
find_package(Protobuf REQUIRED)
list(APPEND PROJECT_LIBRARIES ${Protobuf_LIBRARIES})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${Protobuf_INCLUDE_DIR})
list(APPEND PROJECT_DEFINITIONS "GOOGLE_PROTOBUF_NO_RTTI")

include_directories(${REMILL_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR})

add_executable(mcsema-lift
  EXCLUDE_FROM_ALL
  generated/CFG.pb.cc
  mcsema/Arch/Arch.cpp
  mcsema/CFG/CFG.cpp
  mcsema/BC/External.cpp
  mcsema/BC/Function.cpp
  mcsema/BC/Instruction.cpp
  mcsema/BC/Optimize.cpp
  mcsema/BC/Segment.cpp
  mcsema/BC/Util.cpp
  tools/mcsema_lift/Lift.cpp
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
