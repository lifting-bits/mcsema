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
    circular_buffer.hpp
    circular_buffer_fwd.hpp
    circular_buffer
)

# Add a library target to the build system
boost_library_project(
  circular_buffer
  #  SRCDIRS 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "STL compliant container also known as ring or cyclic buffer."
  MODULARIZED
  AUTHORS  "Jan Gaspar <jano_gaspar -at- yahoo.com>"
  #  MAINTAINERS 
)


