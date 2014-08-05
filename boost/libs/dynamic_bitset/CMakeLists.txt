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
    dynamic_bitset.hpp
    dynamic_bitset_fwd.hpp
    dynamic_bitset
)

# Add a library target to the build system
boost_library_project(
  dynamic_bitset
  #  SRCDIRS 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "A runtime-sized version of std::bitset"
  MODULARIZED
  AUTHORS  "Jeremy Siek <jeremy.siek -at- gmail.com>"
           "Chuck Allison"
  #  MAINTAINERS 
)


