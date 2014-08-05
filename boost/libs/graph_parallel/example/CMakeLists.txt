# Copyright (C) 2008 The Trustees of Indiana University.
#
# Use, modification and distribution is subject to the Boost Software
# License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)

if (MPI_FOUND)

  boost_additional_test_dependencies(graph_parallel BOOST_DEPENDS test mpi filesystem system)

  include_directories(${MPI_INCLUDE_PATH})

  macro(boost_graph_parallel_example testname) 
    PARSE_ARGUMENTS(MPI_EXAMPLE "NUMPROCS;ARGS" "" ${ARGN})

    # Determine the example sources
    if (MPI_EXAMPLE_DEFAULT_ARGS)
      set(MPI_EXAMPLE_SOURCES ${MPI_EXAMPLE_DEFAULT_ARGS})
    else (MPI_EXAMPLE_DEFAULT_ARGS)
      set(MPI_EXAMPLE_SOURCES "${testname}.cpp")
    endif (MPI_EXAMPLE_DEFAULT_ARGS)

    set(THIS_EXAMPLE_LOCATION tests/${BOOST_PROJECT_NAME}/${testname})

    # Build the example executable
    boost_add_executable(${testname} 
      ${MPI_EXAMPLE_SOURCES}
      OUTPUT_NAME ${THIS_EXAMPLE_LOCATION}
      NO_INSTALL
      DEPENDS boost_graph_parallel boost_system
      COMPILE_FLAGS "${MPI_COMPILE_FLAGS}"
      LINK_FLAGS "${MPI_LINK_FLAGS}"
      LINK_LIBS ${MPI_LIBRARIES}
      SHARED_COMPILE_FLAGS "-DBOOST_MPI_DYN_LINK=1")

    if (BUILD_TESTING)  

      if (NOT MPI_EXAMPLE_NUMPROCS)
        set(MPI_EXAMPLE_NUMPROCS ${MPIEXEC_MAX_NUMPROCS})
      endif (NOT MPI_EXAMPLE_NUMPROCS)

      foreach(PROCS ${MPI_EXAMPLE_NUMPROCS})
        add_test("${BOOST_PROJECT_NAME}-${testname}-${PROCS}"
          ${MPIEXEC}
          -n ${PROCS}
          ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${THIS_EXAMPLE_LOCATION}
          ${MPI_EXAMPLE_ARGS}
          ${BOOST_TEST_ARGS}
        )
      endforeach(PROCS)

    endif(BUILD_TESTING)  

  endmacro(boost_graph_parallel_example)

  boost_graph_parallel_example(breadth_first_search ARGS ${Boost_SOURCE_DIR}/libs/graph/test/weighted_graph.gr)
  boost_graph_parallel_example(dijkstra_shortest_paths ARGS ${Boost_SOURCE_DIR}/libs/graph/test/weighted_graph.gr)

endif (MPI_FOUND)
