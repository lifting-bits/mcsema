# Copyright (C) 2008 The Trustees of Indiana University.
#
# Use, modification and distribution is subject to the Boost Software
# License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)

if (NOT MPI_FOUND)
 message(STATUS "+-- MPI not found, disabling.")
else()

  boost_library_project(
    graph_parallel
    SRCDIRS  src
    TESTDIRS  test example
    # HEADERS graph graph/parallel
    # DOCDIRS doc
    DESCRIPTION  "Parallel support using MPI for Boost.Graph."
    AUTHORS  "Douglas Gregor <doug.gregor -at- gmail.com>"
    "Nicholas Edmonds <ngedmond -at- osl.iu.edu>"
    "Jeremiah Willcock <jewillco -at- osl.iu.edu>"
    "Andrew Lumsdaine"
    #  MAINTAINERS 
    )

endif()
