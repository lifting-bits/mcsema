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

if (NOT UNIX)
  message (ERROR "The Dyninst frontend currently does not support this OS")
else ()
  set (CMAKE_CXX_FLAGS "-frtti")
  set (CMAKE_CXX_STANDARD 17)
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
