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
    integer.hpp
    integer_fwd.hpp
    integer_traits.hpp
    integer
)

# Add a library target to the build system
boost_library_project(
  integer
  #  SRCDIRS 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "The organization of boost integer headers and classes is designed to take advantage of <stdint.h> types from the 1999 C standard without resorting to undefined behavior in terms of the 1998 C++ standard. The header <boost/cstdint.hpp> makes the standard integer types safely available in namespace boost without placing any names in namespace std."
  MODULARIZED 
  AUTHORS  "Beman Dawes <bdawes -at- acm.org>"
           "Daryle Walker <darylew -at- hotmail.com>"
  #  MAINTAINERS 
)


