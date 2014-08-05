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
    date_time.hpp
    date_time
)

# Add a library target to the build system
boost_library_project(
  date_time
  SRCDIRS  src 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "A set of date-time libraries based on generic programming concepts."
  MODULARIZED
  AUTHORS  "Jeff Garland <jeff -at- crystalclearsoftware.com>"
  #  MAINTAINERS 
)


