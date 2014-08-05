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
    iostreams
)

# Add a library target to the build system
boost_library_project(
  iostreams
  SRCDIRS  src
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Framework for defining streams, stream buffers and i/o filters"
  MODULARIZED
  AUTHORS  "Jonathan Turkanis <turkanis -at- coderage.com>"
  #  MAINTAINERS 
)


