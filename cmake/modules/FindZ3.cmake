INCLUDE(CheckCXXSourceRuns)

# Function to check Z3's version
function(check_z3_version z3_include z3_lib)
  # Get lib path
  get_filename_component(z3_lib_path ${z3_lib} PATH)

  # Try to find a threading module in case Z3 was built with threading support.
  # Threads are required elsewhere in LLVM, but not marked as required here because
  # Z3 could have been compiled without threading support.
  find_package(Threads)
  set(z3_link_libs "-lz3" "${CMAKE_THREAD_LIBS_INIT}")

  try_run(
    Z3_RETURNCODE
    Z3_COMPILED
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/cmake/modules/testz3.cpp
    COMPILE_DEFINITIONS -I"${z3_include}"
    LINK_LIBRARIES -L${z3_lib_path} ${z3_link_libs}
    RUN_OUTPUT_VARIABLE SRC_OUTPUT
  )

  if(Z3_COMPILED)
    string(REGEX REPLACE "([0-9]*\\.[0-9]*\\.[0-9]*)" "\\1"
           z3_version "${SRC_OUTPUT}")
    set(Z3_VERSION_STRING ${z3_version} PARENT_SCOPE)
  endif()
endfunction(check_z3_version)

# Looking for Z3 in LLVM_Z3_INSTALL_DIR
find_path(Z3_INCLUDE_DIR NAMES z3.h
  NO_DEFAULT_PATH
  PATHS ${LLVM_Z3_INSTALL_DIR}/include
  PATH_SUFFIXES libz3 z3
  )

find_library(Z3_LIBS NAMES z3 libz3
  NO_DEFAULT_PATH
  PATHS ${LLVM_Z3_INSTALL_DIR}
  PATH_SUFFIXES lib bin
  )

# If Z3 has not been found in LLVM_Z3_INSTALL_DIR look in the default directories
find_path(Z3_INCLUDE_DIR NAMES z3.h
  PATH_SUFFIXES libz3 z3
  )

find_library(Z3_LIBS NAMES z3 libz3
  PATH_SUFFIXES lib bin
  )

# Searching for the version of the Z3 library is a best-effort task
unset(Z3_VERSION_STRING)

# First, try to check it dynamically, by compiling a small program that
# prints Z3's version
if(Z3_INCLUDE_DIR AND Z3_LIBS)
  # We do not have the Z3 binary to query for a version. Try to use
  # a small C++ program to detect it via the Z3_get_version() API call.
  check_z3_version(${Z3_INCLUDE_DIR} ${Z3_LIBS})
endif()

# If the dynamic check fails, we might be cross compiling: if that's the case,
# check the version in the headers, otherwise, fail with a message
if(NOT Z3_VERSION_STRING AND (CMAKE_CROSSCOMPILING AND
                              Z3_INCLUDE_DIR AND
                              EXISTS "${Z3_INCLUDE_DIR}/z3_version.h"))
  # TODO: print message warning that we couldn't find a compatible lib?

  # Z3 4.8.1+ has the version is in a public header.
  file(STRINGS "${Z3_INCLUDE_DIR}/z3_version.h"
       z3_version_str REGEX "^#define[\t ]+Z3_MAJOR_VERSION[\t ]+.*")
  string(REGEX REPLACE "^.*Z3_MAJOR_VERSION[\t ]+([0-9]).*$" "\\1"
         Z3_MAJOR "${z3_version_str}")

  file(STRINGS "${Z3_INCLUDE_DIR}/z3_version.h"
       z3_version_str REGEX "^#define[\t ]+Z3_MINOR_VERSION[\t ]+.*")
  string(REGEX REPLACE "^.*Z3_MINOR_VERSION[\t ]+([0-9]).*$" "\\1"
         Z3_MINOR "${z3_version_str}")

  file(STRINGS "${Z3_INCLUDE_DIR}/z3_version.h"
       z3_version_str REGEX "^#define[\t ]+Z3_BUILD_NUMBER[\t ]+.*")
  string(REGEX REPLACE "^.*Z3_BUILD_VERSION[\t ]+([0-9]).*$" "\\1"
         Z3_BUILD "${z3_version_str}")

  set(Z3_VERSION_STRING ${Z3_MAJOR}.${Z3_MINOR}.${Z3_BUILD})
  unset(z3_version_str)
endif()

if(NOT Z3_VERSION_STRING)
  # Give up: we are unable to obtain a version of the Z3 library. Be
  # conservative and force the found version to 0.0.0 to make version
  # checks always fail.
  set(Z3_VERSION_STRING "0.0.0")
endif()

# handle the QUIETLY and REQUIRED arguments and set Z3_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Z3
                                  REQUIRED_VARS Z3_LIBS Z3_INCLUDE_DIR
                                  VERSION_VAR Z3_VERSION_STRING)
if(Z3_FOUND AND NOT TARGET Z3)
  add_library(Z3 UNKNOWN IMPORTED)
  set_target_properties(Z3 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${Z3_INCLUDE_DIR}"
    IMPORTED_LOCATION "${Z3_LIBS}"
  )
  set(Z3_LIBRARIES "Z3")
endif()
mark_as_advanced(Z3_INCLUDE_DIR Z3_LIBS Z3_LIBRARIES)
