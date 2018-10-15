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
# See the License for the specifi

# CMAKE_C_COMPILER or CMAKE_CXX_COMPILER *must* be set before project()
# otherwise it causes infinite loops for some cmake versions

cmake_minimum_required(VERSION 3.3)

set(ListTestsUsage "ListTests(output_variable <windows | linux | macos>)")
function (ListTests output_variable platform)
  if ("${output_variable}" STREQUAL "" OR "${platform}" STREQUAL "")
    message(WARNING "One or more parameters are missing")
    message(FATAL_ERROR "${ListTestsUsage}")
  endif ()

  file(GLOB children LIST_DIRECTORIES true "${CMAKE_CURRENT_SOURCE_DIR}/src/${platform}/*")

  foreach (child ${children})
    if (NOT IS_DIRECTORY "${child}")
      continue ()
    endif ()

    if (NOT EXISTS "${child}/CMakeLists.txt")
      continue ()
    endif ()

    list(APPEND test_list "${child}")
  endforeach ()

  set("${output_variable}" ${test_list} PARENT_SCOPE)
endfunction ()

set(GetArchitectureBitsUsage "GetArchitectureBits(output_variable <x86 | amd64 | aarch64>)")
function (GetArchitectureBits output_variable architecture)
  if ("${output_variable}" STREQUAL "" OR "${architecture}" STREQUAL "")
    message(WARNING "One or more parameters are missing")
    message(FATAL_ERROR "${GetArchitectureBitsUsage}")
  endif ()

  if ("${architecture}" STREQUAL "amd64" OR "${architecture}" STREQUAL "aarch64")
    set("${output_variable}" 64 PARENT_SCOPE)
  elseif ("${architecture}" STREQUAL "x86")
    set("${output_variable}" 32 PARENT_SCOPE)
  else ()
    message(FATAL_ERROR "Unrecognized architecture name: ${architecture}")
  endif ()
endfunction ()

set(GenerateTestUsage "GenerateTest(target_name SOURCES <src1 src2> CXXFLAGS <flag1 flag2> LINKERFLAGS <flag1 flag2>)")
function (GenerateTest target_name)
  if ("${target_name}" STREQUAL "")
    message(WARNING "The target name is missing")
    message(FATAL_ERROR "${GenerateTestUsage}")
  endif ()

  get_filename_component(platform "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)
  get_filename_component(platform "${platform}" NAME)

  foreach (parameter ${ARGN})
    if ("${parameter}" STREQUAL "SOURCES")
      set(state "${parameter}")
      continue ()

    elseif ("${parameter}" STREQUAL "CXXFLAGS")
      set(state "${parameter}")
      continue ()

    elseif ("${parameter}" STREQUAL "LINKERFLAGS")
      set(state "${parameter}")
      continue ()
    endif ()

    if ("${state}" STREQUAL "SOURCES")
      list(APPEND source_file_list "${parameter}")

    elseif ("${state}" STREQUAL "CXXFLAGS")
      list(APPEND cxx_flag_list "${parameter}")

    elseif ("${state}" STREQUAL "LINKERFLAGS")
      list(APPEND linker_flag_list "${parameter}")
    endif ()
  endforeach ()

  foreach (architecture ${ARCHITECTURE_LIST})

    GetArchitectureBits(architecture_bits "${architecture}")
    set(additional_flags "-m${architecture_bits}")


    ######## NODEBUG #############
    set(current_target_name "${target_name}_${architecture}_nd")
    message(" > ${current_target_name}")
    add_executable("${current_target_name}" ${source_file_list})

    set_target_properties("${current_target_name}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${architecture}/${platform}")
    set_target_properties("${current_target_name}" PROPERTIES SUFFIX "")

    target_compile_options("${current_target_name}" PRIVATE ${additional_flags} ${cxx_flag_list})
    target_link_libraries("${current_target_name}" PRIVATE ${additional_flags} ${linker_flag_list})
    install(TARGETS "${current_target_name}" DESTINATION "${architecture}/${platform}")
    ############## end nodebug ###############

    ############### debug #######################
    set(current_target_name "${target_name}_${architecture}_debug")
    message(" > ${current_target_name}")
    add_executable("${current_target_name}" ${source_file_list})

    set_target_properties("${current_target_name}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${architecture}/${platform}")
    set_target_properties("${current_target_name}" PROPERTIES SUFFIX "")

    target_compile_options("${current_target_name}" PRIVATE ${additional_flags} ${cxx_flag_list} "-g3")
    target_link_libraries("${current_target_name}" PRIVATE ${additional_flags} ${linker_flag_list})
    install(TARGETS "${current_target_name}" DESTINATION "${architecture}/${platform}")
    ################### end debug #############################

  endforeach ()
endfunction ()


set(GenerateTestBinaryUsage "GenerateTest(target_name ARCH <architecture> DEBUG <debug binary> NODEBUG <nodebug binary>)")
function (GenerateTestBinary target_name)
  if ("${target_name}" STREQUAL "")
    message(WARNING "The target name is missing")
    message(FATAL_ERROR "${GenerateTestBinaryUsage}")
  endif ()

  get_filename_component(platform "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)
  get_filename_component(platform "${platform}" NAME)

  foreach (parameter ${ARGN})
    if ("${parameter}" STREQUAL "DEBUG")
      set(state "${parameter}")
      continue ()

    elseif ("${parameter}" STREQUAL "NODEBUG")
      set(state "${parameter}")
      continue ()

    elseif ("${parameter}" STREQUAL "ARCH")
      set(state "${parameter}")
      continue ()

    endif ()

    if ("${state}" STREQUAL "DEBUG")
      set(debug_binary "${parameter}")

    elseif ("${state}" STREQUAL "NODEBUG")
      set(nodebug_binary "${parameter}")

    elseif ("${state}" STREQUAL "ARCH")
      set(architecture "${parameter}")
    endif ()
  endforeach ()

  ######## NODEBUG #############
  set(current_target_name "${target_name}_${architecture}_nd")
  message(" > ${current_target_name}")
  install(PROGRAMS "${nodebug_binary}" DESTINATION "${architecture}/${platform}" RENAME "${current_target_name}" )
  ############## end nodebug ###############

  ############### debug #######################
  set(current_target_name "${target_name}_${architecture}_debug")
  message(" > ${current_target_name}")
  install(PROGRAMS "${debug_binary}" DESTINATION "${architecture}/${platform}" RENAME "${current_target_name}" )
  ################### end debug #############################

endfunction ()

set(CMAKE_INSTALL_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/bin")

if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)|(x86_64)")
  set(ARCHITECTURE_LIST x86 amd64)

elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "ARM")
  set(ARCHITECTURE_LIST aarch64)

else ()
  message(FATAL_ERROR "Unrecognized architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif ()

function (main)
  if (WIN32)
    set(platform "windows")
  elseif (APPLE)
    set(platform "macos")
  elseif (UNIX AND NOT APPLE)
    set(platform "linux")
  endif ()

  message("Adding tests...")
  ListTests(platform_test_list "${platform}")
  foreach (test_path ${platform_test_list})
    add_subdirectory("${test_path}")
  endforeach ()

endfunction ()

main()
