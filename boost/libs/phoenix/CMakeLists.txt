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
    phoenix
)

# Add a library target to the build system
boost_library_project(
  phoenix
  #  SRCDIRS 
  TESTDIRS test
  HEADERS ${lib_headers}
  DOCDIRS doc
  DESCRIPTION  "Define small unnamed function objects at the actual call site, and more."
  MODULARIZED 
  AUTHORS  "Joel de Guzman <joel -at- boost-consulting.com>"
           "Dan Marsden"
           "Thomas Heller"
  #  MAINTAINERS 
)


