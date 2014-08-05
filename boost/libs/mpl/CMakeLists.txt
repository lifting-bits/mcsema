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
    mpl
)

# Add a library target to the build system
boost_library_project(
  mpl
  #  SRCDIRS 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "A general-purpose, high-level C++ template metaprogramming framework of compile-time algorithms, sequences and metafunctions. It provides a conceptual foundation and an extensive set of powerful and coherent tools that make doing explict metaprogramming in C++ as easy and enjoyable as possible within the current language."
  MODULARIZED 
  AUTHORS  "Aleksey Gurtovoy <agurtovoy -at- meta-comm.com>"
           "David Abrahams <dave -at- boostpro.com>"
  #  MAINTAINERS 
)


