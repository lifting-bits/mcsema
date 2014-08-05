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
    wave.hpp
    wave
)

# Add a library target to the build system
boost_library_project(wave

  SRCDIRS  src 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "A standards-conformant and highly-configurable implementation of the mandated C99/C++ preprocessor functionality packed behind an easy to use iterator interface."
  MODULARIZED
  AUTHORS  "Hartmut Kaiser <hartmut.kaiser -at- gmail.com>"
  #  MAINTAINERS 
)


