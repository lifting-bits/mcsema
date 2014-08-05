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
    iterator.hpp
    iterator
)

# Add a library target to the build system
boost_library_project(
  iterator
  #  SRCDIRS 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "A system of concepts which extend the C++ standard iterator requirementsand a framework of components for building iterators based on these extended concepts and includes several useful iterator adaptors."
  MODULARIZED 
  AUTHORS  "David Abrahams <dave -at- boostpro.com>"
           "Jeremy Siek <jeremy.siek -at- gmail.com>"
           "Thomas Witt <witt - at - acm.org>"
  #  MAINTAINERS 
)


