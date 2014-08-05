#
# Copyright (c) 2010 Isidor Zeuner
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
#----------------------------------------------------------------------------
# This file was automatically generated from the original CMakeLists.txt file
# Add a variable to hold the headers for the library
set (lib_headers
    uuid
)

# Add a library target to the build system
boost_library_project(
  uuid
  #  SRCDIRS 
  TESTDIRS test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "The header uuid.hpp provides an implementation of Universally Unique Identifiers."
  MODULARIZED
  AUTHORS  "Andy Tompkins"
  #  MAINTAINERS 
)


