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
    property_tree
)

# Add a library target to the build system
boost_library_project(
  property_tree
  # SRCDIRS  src 
  TESTDIRS  test
  EXAMPLEDIRS example
  HEADERS ${lib_headers}
  DOCDIRS doc
  DESCRIPTION  "Data structure storing an arbitrarily deeply nested tree of values, indexed at each level by some key."
  MODULARIZED
  AUTHORS  "Marcin Kalicinski <kalita -at- poczta.onet.pl>"
  #  MAINTAINERS 
)


