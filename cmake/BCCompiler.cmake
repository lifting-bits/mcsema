#
# compiler detection
#

if(DEFINED CMAKE_OSX_SYSROOT)
  set(EXTRA_BC_SYSROOT -isysroot ${CMAKE_OSX_SYSROOT})
endif()

set(DEFAULT_BC_COMPILER_FLAGS
  -emit-llvm -Wno-unknown-warning-option -Wall -Wshadow
  -Wconversion -Wpadded -pedantic -Wshorten-64-to-32 -Wgnu-alignof-expression
  -Wno-gnu-anonymous-struct -Wno-return-type-c-linkage
  -Wno-gnu-zero-variadic-macro-arguments -Wno-nested-anon-types
  -Wno-extended-offsetof -Wno-gnu-statement-expression -Wno-c99-extensions
  -Wno-ignored-attributes -mtune=generic -fno-vectorize -fno-slp-vectorize
  -Wno-variadic-macros -Wno-c11-extensions -Wno-c++11-extensions
  -ffreestanding -fno-common -fno-builtin -fno-exceptions -fno-rtti
  -fno-asynchronous-unwind-tables -Wno-unneeded-internal-declaration
  -Wno-unused-function -Wgnu-inline-cpp-without-extern -std=c++14
  -Wno-pass-failed=transform-warning
  ${EXTRA_BC_SYSROOT}
)

find_package(Clang CONFIG REQUIRED)
get_target_property(CLANG_PATH clang LOCATION)
get_target_property(LLVMLINK_PATH llvm-link LOCATION)

file(WRITE "${CMAKE_BINARY_DIR}/emitllvm.test.cpp" "int main(int argc, char* argv[]){return 0;}\n\n")

execute_process(COMMAND "${CLANG_PATH}" "-emit-llvm" "-c" "emitllvm.test.cpp" "-o" "emitllvm.test.cpp.bc"
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  RESULT_VARIABLE AOUT_IS_NOT_BC
  OUTPUT_QUIET ERROR_QUIET
)

if(NOT "${AOUT_IS_NOT_BC}" STREQUAL "0")
  message(SEND_ERROR "The following compiler is not suitable to generate bitcode: ${CLANG_PATH}")
else()
  message(STATUS "The following compiler has been selected to compile the bitcode: ${CLANG_PATH}")
  message(STATUS "The following linker has been selected to link the bitcode: ${LLVMLINK_PATH}")

  set(CMAKE_BC_COMPILER "${CLANG_PATH}" CACHE PATH "Bitcode Compiler")
  set(CMAKE_BC_LINKER "${LLVMLINK_PATH}" CACHE PATH "Bitcode Linker")
endif()

#
# utils
#

# this is the runtime target generator, used in a similar way to add_executable
set(add_runtime_usage "add_runtime(target_name SOURCES <src1 src2> ADDRESS_SIZE <size> DEFINITIONS <def1 def2> BCFLAGS <bcflag1 bcflag2> LINKERFLAGS <lnkflag1 lnkflag2> INCLUDEDIRECTORIES <path1 path2> INSTALLDESTINATION <path> DEPENDENCIES <dependency1 dependency2>")

function(add_runtime target_name)
  if(NOT DEFINED CMAKE_BC_COMPILER)
    message(FATAL_ERROR "The bitcode compiler was not found!")
  endif()

  if(NOT DEFINED CMAKE_BC_LINKER)
    message(FATAL_ERROR "The bitcode linker was not found!")
  endif()

  foreach(macro_parameter ${ARGN})
    if("${macro_parameter}" STREQUAL "SOURCES")
      set(state "${macro_parameter}")
      continue()

    elseif("${macro_parameter}" STREQUAL "ADDRESS_SIZE")
      set(state "${macro_parameter}")
      continue()

    elseif("${macro_parameter}" STREQUAL "DEFINITIONS")
      set(state "${macro_parameter}")
      continue()

    elseif("${macro_parameter}" STREQUAL "BCFLAGS")
      set(state "${macro_parameter}")
      continue()

    elseif("${macro_parameter}" STREQUAL "LINKERFLAGS")
      set(state "${macro_parameter}")
      continue()

    elseif("${macro_parameter}" STREQUAL "INCLUDEDIRECTORIES")
      set(state "${macro_parameter}")
      continue()

    elseif("${macro_parameter}" STREQUAL "INSTALLDESTINATION")
      set(state "${macro_parameter}")
      continue()

    elseif("${macro_parameter}" STREQUAL "DEPENDENCIES")
      set(state "${macro_parameter}")
      continue()
    endif()

    if("${state}" STREQUAL "SOURCES")
      list(APPEND source_file_list "${macro_parameter}")

    elseif("${state}" STREQUAL "ADDRESS_SIZE")
      if(DEFINED address_size_bits_found)
        message(SEND_ERROR "The ADDRESS_SIZE parameter has been specified twice!")
      endif()

      if(NOT "${macro_parameter}" MATCHES "^[0-9]+$")
        message(SEND_ERROR "Invalid ADDRESS_SIZE parameter passed to add_runtime")
      endif()

      set(address_size "${macro_parameter}")
      set(address_size_bits_found True)

    elseif("${state}" STREQUAL "DEFINITIONS")
      list(APPEND definition_list "-D${macro_parameter}")

    elseif("${state}" STREQUAL "BCFLAGS")
      list(APPEND bc_flag_list "${macro_parameter}")

    elseif("${state}" STREQUAL "LINKERFLAGS")
      list(APPEND linker_flag_list "${macro_parameter}")

    elseif("${state}" STREQUAL "INCLUDEDIRECTORIES")
      list(APPEND include_directory_list "-I${macro_parameter}")

    elseif("${state}" STREQUAL "INSTALLDESTINATION")
      if(DEFINED install_destination)
        message("The INSTALLDESTINATION parameter has been specified twice!")
      endif()

      set(install_destination "${macro_parameter}")

    elseif("${state}" STREQUAL "DEPENDENCIES")
      list(APPEND dependency_list "${macro_parameter}")

    else()
      message(SEND_ERROR "Syntax error. Usage: ${add_runtime_usage}")
    endif()
  endforeach()

  if(NOT address_size_bits_found)
    message(SEND_ERROR "Missing address size.")
  endif()

  if("${source_file_list}" STREQUAL "")
    message(SEND_ERROR "No source files specified.")
  endif()

  foreach(source_file ${source_file_list})
    get_filename_component(source_file_name "${source_file}" NAME)
    get_filename_component(absolute_source_file_path "${source_file}" ABSOLUTE)
    set(absolute_output_file_path "${CMAKE_CURRENT_BINARY_DIR}/${target_name}_${source_file_name}.bc")

    get_property(source_file_properties SOURCE "${absolute_source_file_path}" PROPERTY COMPILE_FLAGS)
    string(REPLACE " " ";" source_file_option_list "${source_file_properties}")

    if(NOT "${dependency_list}" STREQUAL "")
      set(dependency_list_directive DEPENDS ${dependency_list})
    endif()

    if(WIN32)
      # We are actually using two different compilers; the LLVM platform toolset downloaded
      # from the official LLVM download page and our own version from the cxx-common tarball.
      #
      # When the versions do not match, the compilation will fail; we don't really care about
      # this, as the second compiler is only really used to output BC files.
      set(additional_windows_settings "-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH")
    endif()

    add_custom_command(OUTPUT "${absolute_output_file_path}"
      COMMAND "${CMAKE_BC_COMPILER}" ${include_directory_list} ${additional_windows_settings} "-DADDRESS_SIZE_BITS=${address_size}" ${definition_list} ${DEFAULT_BC_COMPILER_FLAGS} ${bc_flag_list} ${source_file_option_list} -c "${absolute_source_file_path}" -o "${absolute_output_file_path}"
      MAIN_DEPENDENCY "${absolute_source_file_path}"
      ${dependency_list_directive}
      COMMENT "Building BC object ${absolute_output_file_path}"
    )

    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${absolute_output_file_path}")
    list(APPEND bitcode_file_list "${absolute_output_file_path}")
  endforeach()

  set(absolute_target_path "${CMAKE_CURRENT_BINARY_DIR}/${target_name}.bc")

  add_custom_command(OUTPUT "${absolute_target_path}"
    COMMAND "${CMAKE_BC_LINKER}" ${linker_flag_list} ${bitcode_file_list} -o "${absolute_target_path}"
    DEPENDS ${bitcode_file_list}
    COMMENT "Linking BC runtime ${absolute_target_path}"
  )

  set(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${absolute_target_path}")

  add_custom_target("${target_name}" ALL DEPENDS "${absolute_target_path}")
  set_property(TARGET "${target_name}" PROPERTY LOCATION "${absolute_target_path}")

  if(DEFINED install_destination)
    install(FILES "${absolute_target_path}" DESTINATION "${install_destination}")
  endif()
endfunction()
