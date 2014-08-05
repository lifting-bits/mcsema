#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
#----------------------------------------------------------------------------
# This file was automatically generated from the original CMakeLists.txt file
# Add a variable to hold the headers for the library
set (lib_headers
    regex.h
    regex.hpp
    regex_fwd.hpp
    regex
    cregex.hpp
)

# TODO: Default to multi-threaded?
#
# Used in test/ and examples/
#
macro(regex_test TESTNAME)
  parse_arguments(REGEX_TEST "" "" ${ARGN})

  if (REGEX_TEST_DEFAULT_ARGS)
    set(REGEX_TEST_SOURCES ${REGEX_TEST_DEFAULT_ARGS})
  else (REGEX_TEST_DEFAULT_ARGS)
    set(REGEX_TEST_SOURCES "${TESTNAME}.cpp")
  endif (REGEX_TEST_DEFAULT_ARGS)

  boost_test_run(${TESTNAME} ${REGEX_TEST_SOURCES} 
    COMPILE_FLAGS "-DBOOST_REGEX_DYN_LINK=1"
    DEPENDS boost_regex 
    EXTRA_OPTIONS SHARED)
endmacro(regex_test)

# Add a library target to the build system
boost_library_project(
  regex
  SRCDIRS  src
  TESTDIRS  test
  EXAMPLEDIRS  example
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "A regular expression library"
  MODULARIZED
  AUTHORS  "John Maddock <john -at- johnmaddock.co.uk>"
  #  MAINTAINERS 
)


