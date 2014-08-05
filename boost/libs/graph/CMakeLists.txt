# Copyright (C) 2008 Michael Jackson
#
# Use, modification and distribution is subject to the Boost Software
# License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)

#----------------------------------------------------------------------------
# This file was automatically generated from the original CMakeLists.txt file

# Add a library target to the build system
boost_library_project(
  graph
  SRCDIRS  src 
  TESTDIRS  test
  HEADERS graph
  #  DOCDIRS 
  DESCRIPTION  "The BGL graph interface and graph components are generic, in the same sense as the the Standard Template Library (STL)."
  MODULARIZED
  AUTHORS  "Jeremy Siek <jeremy.siek -at- gmail.com>"
           "Lie-Quan Lee"
           "Andrew Lumsdaine"
           "Douglas Gregor <doug.gregor -at- gmail.com>"
  #  MAINTAINERS 
)
