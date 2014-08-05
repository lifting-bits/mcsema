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
    optional.hpp
    optional
)

# Add a library target to the build system
boost_library_project(
  optional
  #  SRCDIRS 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  #  DESCRIPTION 
  MODULARIZED 
  #  AUTHORS 
  #  MAINTAINERS 
)


