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
    tr1
)

# Add a library target to the build system
boost_library_project(
  tr1
  #  SRCDIRS 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "An implementation of the C++ Technical Report on Standard Library Extensions. This library does not itself implement the TR1 components, rather it's a thin wrapper that will include your standard library's TR1 implementation (if it has one), otherwise it will include the Boost Library equivalents, and import them into namespace std::tr1."
  MODULARIZED
  AUTHORS  "John Maddock <john -at- johnmaddock.co.uk>"
  #  MAINTAINERS 
)


