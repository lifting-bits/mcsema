# Copyright (C) 2008 The Trustees of Indiana University.
#
# Use, modification and distribution is subject to the Boost Software
# License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)

add_definitions(-DBOOST_GRAPH_NO_LIB=1)

if (MSVC)
  # Without these flags, MSVC 7.1 and 8.0 crash
  add_definitions(-GR-)
endif (MSVC)

# Add Boost.MPI link and add parallel source files
include_directories(${MPI_INCLUDE_PATH})

boost_add_library(
  graph_parallel
  mpi_process_group.cpp tag_allocator.cpp
  DEPENDS boost_mpi
  SHARED_COMPILE_FLAGS "-DBOOST_GRAPH_DYN_LINK=1"
  )
