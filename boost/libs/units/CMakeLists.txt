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
    units
)

# Add a library target to the build system
boost_library_project(
  units
  #  SRCDIRS 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Zero-overhead dimensional analysis and unit/quantity manipulation and conversion."
  MODULARIZED
  AUTHORS  "Matthias Schabel <boost -at- schabel-family.org>"
           "Steven Watanabe <steven -at- providere-consulting.com>"
  #  MAINTAINERS 
)


