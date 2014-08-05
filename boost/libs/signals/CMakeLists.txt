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
    signals.hpp
    signal.hpp
    signals
)

# Add a library target to the build system
boost_library_project(
  signals
  SRCDIRS  src 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Managed signals & slots callback implementation."
  MODULARIZED
  AUTHORS  "Douglas Gregor <doug.gregor -at- gmail.com>"
  #  MAINTAINERS 
)


