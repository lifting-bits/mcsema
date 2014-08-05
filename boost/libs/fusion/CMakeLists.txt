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
    fusion
)

# Add a library target to the build system
boost_library_project(
  fusion
  #  SRCDIRS 
  #  TESTDIRS 
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Library for working with tuples, including various containers, algorithms, etc."
  MODULARIZED
  AUTHORS  "Joel de Guzman <joel -at- boost-consulting.com>"
           "Dan Marsden <danmarsden -at- yahoo.co.uk>"
           "Tobias Schwinger <tschwinger -at- isonews2.com>"
  #  MAINTAINERS 
)


