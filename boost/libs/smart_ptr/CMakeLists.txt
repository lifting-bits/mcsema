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
    enable_shared_from_this.hpp
    pointer_cast.hpp
    scoped_array.hpp
    scoped_ptr.hpp
    shared_array.hpp
    shared_ptr.hpp
    weak_ptr.hpp
)

# Add a library target to the build system
boost_library_project(
  smart_ptr
  #  SRCDIRS 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Five smart pointer class templates."
  MODULARIZED 
  AUTHORS  "Greg Colvin"
           "Beman Dawes <bdawes -at- acm.org>"
           "Peter Dimov <pdimov -at- mmltd.net>"
           "Darin Adler"
  #  MAINTAINERS 
)


