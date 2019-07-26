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

if (NOT UNIX)
  message (ERROR "The Dyninst frontend currently does not support this OS")
else ()
  add_compile_options(-frtti -std=c++14)
  set (CMAKE_CXX_FLAGS "-frtti")
  set (CMAKE_CXX_FLAGS "-std=c++14")
endif ()

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

find_package(Dyninst REQUIRED)
include_directories(${DYNINST_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../../)

set(MCSEMA_DYNINST_DISASS mcsema-dyninst-disass)


set_source_files_properties(
  ${PROJECT_PROTOBUFSOURCEFILES}
  PROPERTIES GENERATED TRUE
  )

add_executable(${MCSEMA_DYNINST_DISASS}
  ${PROJECT_PROTOBUFSOURCEFILES}
  main.cpp
  CFGWriter.cpp
  ExternalFunctionManager.cpp
  SectionManager.cpp
  SectionParser.cpp
  MagicSection.cpp
  Util.cpp
  OffsetTable.cpp
  )

target_link_libraries(${MCSEMA_DYNINST_DISASS} PRIVATE symtabAPI parseAPI instructionAPI common)
target_link_libraries(${MCSEMA_DYNINST_DISASS} PRIVATE ${PROJECT_LIBRARIES})
target_include_directories(${MCSEMA_DYNINST_DISASS} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${MCSEMA_DYNINST_DISASS} PUBLIC ${PROJECT_DEFINITIONS})

#set_property(TARGET ${MCSEMA_DYNINST_DISASS} APPEND PROPERTY CMAKE_CXX_FLAGS -frtti)
set_target_properties(${MCSEMA_DYNINST_DISASS} PROPERTIES CXX_STANDARD 14 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)

install(
  TARGETS ${MCSEMA_DYNINST_DISASS}
  RUNTIME DESTINATION bin
  )
