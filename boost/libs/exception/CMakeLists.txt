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
    exception.hpp
    exception_ptr.hpp
    exception
)

# Add a library target to the build system
boost_library_project(
  exception
  #  SRCDIRS 
  TESTDIRS  test 
  HEADERS ${lib_headers}
  DOCDIRS  doc
  DESCRIPTION  "A library for transporting of arbitrary data in exception objects, and transporting of exceptions between threads."
  MODULARIZED 
  AUTHORS  "Emil Dotchevski <emil -at- revergestudios.com>"
  #  MAINTAINERS 
)


