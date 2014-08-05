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
    mpi.hpp
    mpi
)

if (NOT MPI_FOUND)
  colormsg(RED "+-- MPI not found, disabling.")
else()

  boost_library_project(
    mpi
    SRCDIRS   src
    TESTDIRS  test
    HEADERS   ${lib_headers}
    DOCDIRS   doc
    #  DESCRIPTION 
    MODULARIZED
    #  AUTHORS 
    #  MAINTAINERS 
    )

endif()
