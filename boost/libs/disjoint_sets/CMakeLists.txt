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
    
)

# Add a library target to the build system
boost_library_project(
  disjoint_sets
  #  SRCDIRS 
  TESTDIRS  test
#  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Provides disjoint sets operations with union by rank and path compression."
 # MODULARIZED 
  AUTHORS  "Jeremy Siek <jeremy.siek -at- gmail.com>"
           "Lie-Quan Lee"
           "Andrew Lumsdaine"
  #  MAINTAINERS 
)


