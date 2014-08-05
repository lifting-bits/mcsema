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
    program_options.hpp
    program_options
)

# Add a library target to the build system
boost_library_project(
  program_options
  SRCDIRS  src
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Access to configuration data given on command line, in config files and other sources."
  MODULARIZED
  AUTHORS  "Vladimir Prus <ghost -at- cs.msu.su>"
  #  MAINTAINERS 
)


