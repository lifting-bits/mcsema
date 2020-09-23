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

# CMAKE_C_COMPILER or CMAKE_CXX_COMPILER *must* be set before project()
# otherwise it causes infinite loops for some cmake versions
# see: https://cmake.org/Bug/view.php?id=14841
set(CLANG_PATH "$ENV{TRAILOFBITS_LIBRARIES}/llvm/bin/clang")
set(CLANGXX_PATH "$ENV{TRAILOFBITS_LIBRARIES}/llvm/bin/clang++")
set(CMAKE_ADA_COMPILER_ID_RUN 1)

if (NOT "${CMAKE_CXX_COMPILER}" STREQUAL "${CLANGXX_PATH}")
  set(CMAKE_CXX_COMPILER "${CLANGXX_PATH}")
endif ()
if (NOT "${CMAKE_C_COMPILER}" STREQUAL "${CLANG_PATH}")
  set(CMAKE_C_COMPILER "${CLANG_PATH}")
endif ()

project(mcsema_test_suite)
cmake_minimum_required(VERSION 3.5)

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

  install(
    FILES "src/start.py"
    DESTINATION "${CMAKE_INSTALL_PREFIX}"
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                GROUP_READ GROUP_WRITE GROUP_EXECUTE
                WORLD_READ WORLD_EXECUTE
  )
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

set(GenerateBinaryOutputUsage "GenerateBinaryOutput(target_name binary_path architecture)")
function (GenerateBinaryOutput target_name binary_path architecture)
  if ("${target_name}" STREQUAL "" OR "${binary_path}" STREQUAL "" OR "${architecture}" STREQUAL "")
    message(WARNING "One or more parameters are missing")
    message(FATAL_ERROR "${GenerateBinaryOutputUsage}")
  endif ()

  get_filename_component(platform "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)
  get_filename_component(platform "${platform}" NAME)

  set(output_file "${target_name}_${architecture}.stdout")

  if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/input")
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/input" test_input)
    string(REGEX REPLACE ";" "\\\\;" test_input "${test_input}")
    string(REGEX REPLACE "\n" ";" test_input "${test_input}")

    foreach (test_input_line ${test_input})
      list(APPEND command_list COMMAND "${binary_path}" ${test_input_line} >> "${output_file}" 2>&1)
    endforeach ()

    install(FILES "input" DESTINATION "${architecture}/${platform}/input" RENAME "${target_name}")

  else ()
    list(APPEND command_list COMMAND "${binary_path}" > "${output_file}" 2>&1)
  endif ()

  file(REMOVE "${output_file}")
  add_custom_command(
    OUTPUT "${output_file}"
    ${command_list}
    DEPENDS "${binary_path}"
    VERBATIM
  )

  add_custom_target("${target_name}_${architecture}_stdout" ALL DEPENDS "${output_file}")
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${output_file}" DESTINATION "${architecture}/${platform}/stdout" RENAME "${target_name}")
endfunction ()

set(ExportCFGUsage "ExportCFG(target_name architecture binary_path)")
function (ExportCFG target_name architecture binary_path)
  if ("${target_name}" STREQUAL "" OR "${binary_path}" STREQUAL "" OR "${architecture}" STREQUAL "")
    message(WARNING "One or more parameters are missing")
    message(FATAL_ERROR "${GenerateBinaryOutputUsage}")
  endif ()

  set(output_file "${target_name}_${architecture}.cfg")

  if ("${IDAT64_PATH}" STREQUAL "IDAT64_PATH-NOTFOUND")
    #Read CFG from pre-built CFG repository
    #configure_file("${MCSEMA_PREBUILT_CFG_PATH}/${architecture}/${platform}/cfg/${target_name}"
    #               "${output_file}"
    #               COPYONLY)
    add_custom_command(
      OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${output_file}"
      COMMAND cmake -E copy
        "${MCSEMA_PREBUILT_CFG_PATH}/${architecture}/${platform}/cfg/${target_name}"
        "${CMAKE_CURRENT_BINARY_DIR}/${output_file}"
      DEPENDS "${MCSEMA_PREBUILT_CFG_PATH}/${architecture}/${platform}/cfg/${target_name}"
    )
  else ()
    add_custom_command(
      OUTPUT "${output_file}"
      COMMAND "${MCSEMADISASS_EXE}" --disassembler "${IDAT64_PATH}" --arch "${architecture}" --os "${platform}" --binary "${binary_path}" --output "${output_file}" --entrypoint main
      DEPENDS "${binary_path}"
      VERBATIM
    )
  endif ()

  add_custom_target("${target_name}_${architecture}_cfg" ALL DEPENDS "${output_file}")
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${output_file}" DESTINATION "${architecture}/${platform}/cfg" RENAME "${target_name}")
endfunction ()

set(AddBinaryTestUsage "AddBinaryTest(target_name BINARY <bin> CXXFLAGS <flag1 flag2> LINKERFLAGS <flag1 flag2> ARCHITECTURE <x86 | amd64 | aarch64>)")
function (AddBinaryTest target_name)
  if ("${target_name}" STREQUAL "")
    message(WARNING "The target name is missing")
    message(FATAL_ERROR "${AddBinaryTestUsage}")
  endif ()

  get_filename_component(platform "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)
  get_filename_component(platform "${platform}" NAME)

  foreach (parameter ${ARGN})
    if ("${parameter}" STREQUAL "BINARY")
      set(state "${parameter}")
      continue ()

    elseif ("${parameter}" STREQUAL "CXXFLAGS")
      set(state "${parameter}")
      continue ()

    elseif ("${parameter}" STREQUAL "LINKERFLAGS")
      set(state "${parameter}")
      continue ()
    
    elseif ("${parameter}" STREQUAL "ARCHITECTURE")
      set(state "${parameter}")
    endif ()

    if ("${state}" STREQUAL "BINARY")
      if (NOT "${binary_name}" STREQUAL "")
        message(WARNING "Only one binary may be specified when using the BINARY directive")
        message(FATAL_ERROR "${AddBinaryTestUsage}")
      endif ()

      set(binary_name "${parameter}")

    elseif ("${state}" STREQUAL "CXXFLAGS")
      list(APPEND cxx_flag_list "${parameter}")

    elseif ("${state}" STREQUAL "LINKERFLAGS")
      list(APPEND linker_flag_list "${parameter}")

    elseif ("${state}" STREQUAL "ARCHITECTURE")
      set(architecture "${parameter}")
    endif ()
  endforeach ()

  message(" > ${target_name}")

  set(binary_path "${CMAKE_CURRENT_SOURCE_DIR}/${target_name}")  
  GenerateBinaryOutput("${target_name}" "${binary_path}" "${architecture}")

  if ("${architecture}" STREQUAL "amd64" OR "${architecture}" STREQUAL "x86")
    ExportCFG("${target_name}" "${architecture}" "${binary_path}")

    set(cfg_file_name "${target_name}_${architecture}.cfg")
    set(bc_file_name "${target_name}_${architecture}.bc")

    add_custom_command(
      OUTPUT "${bc_file_name}"
      COMMAND "${MCSEMALIFT_EXE}" --arch "${architecture}" --os "${platform}" --cfg "${cfg_file_name}" --output "${bc_file_name}"
      DEPENDS "${cfg_file_name}"
      VERBATIM
    )

    add_custom_target("${target_name}_${architecture}_bc" ALL DEPENDS "${bc_file_name}")

    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${bc_file_name}" DESTINATION "${architecture}/${platform}/bc" RENAME "${target_name}")  
  endif ()

  install(FILES "${binary_path}" DESTINATION "${architecture}/${platform}/bin")
  install(FILES "${target_name}.txt" DESTINATION "${architecture}/${platform}/docs" RENAME "${target_name}")

  set(cxx_flags_file_path "${CMAKE_CURRENT_BINARY_DIR}/${current_target_name}_cxxflags")
  file(WRITE "${cxx_flags_file_path}" "${cxx_flag_list}")
  install(FILES "${cxx_flags_file_path}" DESTINATION "${architecture}/${platform}/cppflags" RENAME "${target_name}")

  set(linker_flags_file_path "${CMAKE_CURRENT_BINARY_DIR}/${current_target_name}_linkerflags")
  file(WRITE "${linker_flags_file_path}" "${linker_flag_list}")
  install(FILES "${linker_flags_file_path}" DESTINATION "${architecture}/${platform}/linkerflags" RENAME "${target_name}")
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
    if("${source_file_list}" MATCHES "\.adb")
      if(${architecture} STREQUAL "x86")
        message(" > skipping x86 support for ADA target: ${target_name}")
        continue()
      endif()
    endif()
    message(" > ${target_name} (${architecture})")
    set(current_target_name "${target_name}_${architecture}")

    GetArchitectureBits(architecture_bits "${architecture}")
    set(additional_flags "-m${architecture_bits}")

    add_executable("${current_target_name}" ${source_file_list})
    set_target_properties("${current_target_name}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${architecture}/${platform}")
    set_target_properties("${current_target_name}" PROPERTIES OUTPUT_NAME "${target_name}")
    set_target_properties("${current_target_name}" PROPERTIES SUFFIX "")

    target_compile_options("${current_target_name}" PRIVATE ${additional_flags} ${cxx_flag_list})
    target_link_libraries("${current_target_name}" PRIVATE ${additional_flags} ${linker_flag_list})

    GenerateBinaryOutput("${target_name}" $<TARGET_FILE:${current_target_name}> "${architecture}")

    if ("${architecture}" STREQUAL "amd64" OR "${architecture}" STREQUAL "x86")
      ExportCFG("${target_name}" "${architecture}" $<TARGET_FILE:${current_target_name}>)

      add_custom_command(
        OUTPUT "${current_target_name}.bc"
	COMMAND "${MCSEMALIFT_EXE}" --arch "${architecture}" --os "${platform}" --cfg "${current_target_name}.cfg" --output "${current_target_name}.bc"
        DEPENDS "${current_target_name}.cfg"
        VERBATIM
      )
  
      add_custom_target("${current_target_name}_bc" ALL DEPENDS "${current_target_name}.bc")

      install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${current_target_name}.bc" DESTINATION "${architecture}/${platform}/bc" RENAME "${target_name}")
    endif ()

    install(TARGETS "${current_target_name}" DESTINATION "${architecture}/${platform}/bin")
    install(FILES "${target_name}.txt" DESTINATION "${architecture}/${platform}/docs" RENAME "${target_name}")

    get_target_property(full_cxx_flags "${current_target_name}" COMPILE_OPTIONS)
    if ("${full_cxx_flags}" STREQUAL "full_cxx_flags-NOTFOUND")
      unset(full_cxx_flags)
    endif ()

    get_target_property(full_linker_flags "${current_target_name}" LINK_LIBRARIES)
    if ("${full_linker_flags}" STREQUAL "full_linker_flags-NOTFOUND")
      unset(full_linker_flags)
    endif ()

    set(cxx_flags_file_path "${CMAKE_CURRENT_BINARY_DIR}/${current_target_name}_cxxflags")
    file(WRITE "${cxx_flags_file_path}" "${cxx_flag_list}")
    install(FILES "${cxx_flags_file_path}" DESTINATION "${architecture}/${platform}/cppflags" RENAME "${target_name}")

    set(linker_flags_file_path "${CMAKE_CURRENT_BINARY_DIR}/${current_target_name}_linkerflags")
    file(WRITE "${linker_flags_file_path}" "${linker_flag_list}")
    install(FILES "${linker_flags_file_path}" DESTINATION "${architecture}/${platform}/linkerflags" RENAME "${target_name}")
  endforeach ()
endfunction ()

if ("$ENV{TRAILOFBITS_LIBRARIES}" STREQUAL "")
  message(FATAL_ERROR "The TRAILOFBITS_LIBRARIES environment variable has not been defined!")
endif ()

string(REPLACE "." ";" LLVM_VERSION_LIST ${CMAKE_CXX_COMPILER_VERSION})
list(GET LLVM_VERSION_LIST 0 LLVM_VERSION_MAJOR)
list(GET LLVM_VERSION_LIST 1 LLVM_VERSION_MINOR)

set(LLVM_VERSION_SUFFIX "-${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}")

find_program(MCSEMALIFT_PATH "mcsema-lift${LLVM_VERSION_SUFFIX}")
if ("${MCSEMALIFT_PATH}" STREQUAL "MCSEMALIFT_PATH-NOTFOUND")
  message(FATAL_ERROR "Failed to locate the mcsema-lift${LLVM_VERSION_SUFFIX} executable!")
endif ()
set(MCSEMALIFT_EXE "${MCSEMALIFT_PATH}")

find_program(IDAT64_PATH "idat64")
if ("${IDAT64_PATH}" STREQUAL "IDAT64_PATH-NOTFOUND")
  message(WARNING "Failed to locate the idat64 executable! Will not test CFG recovery.")
  if(NOT DEFINED MCSEMA_PREBUILT_CFG_PATH)
    message(FATAL_ERROR "IDAT64_PATH is not defined and MCSEMA_PREBUILT_CFG_PATH is not defined (use -DMCSEMA_PREBUILT_CFG_PATH=<path>)")
  endif()
  get_filename_component(MCSEMA_PREBUILT_CFG_PATH "${MCSEMA_PREBUILT_CFG_PATH}" ABSOLUTE)
  if(NOT EXISTS "${MCSEMA_PREBUILT_CFG_PATH}")
    message(FATAL_ERROR "IDA64_PATH not found and I could not find path for prebuilt CFGs. Looked in: ${MCSEMA_PREBUILT_CFG_PATH}")
  endif()
endif ()

find_program(MCSEMADISASS_PATH "mcsema-disass$")
if ("${MCSEMADISASS_PATH}" STREQUAL "MCSEMADISASS_PATH-NOTFOUND")
  message(FATAL_ERROR "Failed to locate the mcsema-disass executable!")
endif ()
set(MCSEMADISASS_EXE "${MCSEMADISASS_PATH}")

message("Toolset")
message(" > mcsema-lift: ${MCSEMALIFT_EXE}")
message(" > clang: ${CLANG_PATH}")
if (NOT "${IDAT64_PATH}" STREQUAL "IDAT64_PATH-NOTFOUND")
  message(" > idat64: ${IDAT64_PATH}")
else()
  message(" > using prebuilt cfgs: ${MCSEMA_PREBUILT_CFG_PATH}")
endif ()
message(" > mcsema-disass: ${MCSEMADISASS_EXE}")

set(CMAKE_INSTALL_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/test_suite")

if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)|(x86_64)")
  if(APPLE)
    set(ARCHITECTURE_LIST amd64)
  else()
    set(ARCHITECTURE_LIST x86 amd64)
  endif()

elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "ARM")
  set(ARCHITECTURE_LIST aarch64)

else ()
  message(FATAL_ERROR "Unrecognized architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif ()

main()
