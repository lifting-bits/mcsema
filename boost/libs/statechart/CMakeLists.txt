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
    statechart
)

# Add a library target to the build system
boost_library_project(
  statechart
  #  SRCDIRS 
  TESTDIRS  test example
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Arbitrarily complex finite state machines can be implemented in easily readable and maintainable C++ code."
  MODULARIZED
  AUTHORS  "Andreas Huber <ahd6974-boostorg -at- yahoo.com>"
  #  MAINTAINERS 
)


