# Copyright (C) 2008 The Trustees of Indiana University.
#
# Use, modification and distribution is subject to the Boost Software
# License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)

if (MPI_FOUND)

  boost_additional_test_dependencies(graph_parallel BOOST_DEPENDS test mpi filesystem system)

  include_directories(${MPI_INCLUDE_PATH})

  # Declare a test for the Boost.MPI library, which may involve both
  # building the test and executing it with varying numbers of
  # processes.  Edited to become boost_graph_parallel_test, with a different
  # default number of processors.
  #
  #     boost_graph_parallel_test(testname
  #                               [source1 source2 ...]
  #                               [ARGS arg1 arg2 ...]
  #                               [SCHEDULE procs1 procs2 ...]
  #
  # testname is the name of the test. source1, source2, etc. are the
  # source files that will be built and linked into the test
  # executable. If no source files are provided, the file "testname.cpp"
  # will be used instead.
  macro(boost_graph_parallel_test testname) 
    PARSE_ARGUMENTS(MPI_TEST "NUMPROCS;ARGS" "" ${ARGN})

    # Determine the test sources
    if (MPI_TEST_DEFAULT_ARGS)
      set(MPI_TEST_SOURCES ${MPI_TEST_DEFAULT_ARGS})
    else (MPI_TEST_DEFAULT_ARGS)
      set(MPI_TEST_SOURCES "${testname}.cpp")
    endif (MPI_TEST_DEFAULT_ARGS)

    set(THIS_TEST_LOCATION tests/${BOOST_PROJECT_NAME}/${testname})

    # Build the test executable
    boost_add_executable(${testname} 
      ${MPI_TEST_SOURCES}
      OUTPUT_NAME ${THIS_TEST_LOCATION}
      NO_INSTALL
      DEPENDS boost_graph_parallel boost_system
      COMPILE_FLAGS "${MPI_COMPILE_FLAGS}"
      LINK_FLAGS "${MPI_LINK_FLAGS}"
      LINK_LIBS ${MPI_LIBRARIES}
      SHARED_COMPILE_FLAGS "-DBOOST_MPI_DYN_LINK=1")

    if (NOT MPI_TEST_NUMPROCS)
      set(MPI_TEST_NUMPROCS ${MPIEXEC_MAX_NUMPROCS})
    endif (NOT MPI_TEST_NUMPROCS)

    foreach(PROCS ${MPI_TEST_NUMPROCS})
      add_test("${BOOST_PROJECT_NAME}-${testname}-${PROCS}"
        ${MPIEXEC}
        -n ${PROCS}
	${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${THIS_TEST_LOCATION}
	${MPI_TEST_ARGS}
        ${BOOST_TEST_ARGS}
        )
    endforeach(PROCS)

  endmacro(boost_graph_parallel_test)

  boost_graph_parallel_test(distributed_property_map_test)
  boost_graph_parallel_test(distributed_queue_test)
  boost_graph_parallel_test(process_group_serialization)
  boost_graph_parallel_test(adjlist_build_test)
  boost_graph_parallel_test(adjlist_redist_test)
  boost_graph_parallel_test(adjlist_remove_test NUMPROCS 2)
  boost_graph_parallel_test(distributed_adjacency_list_test)
  boost_graph_parallel_test(distributed_connected_components_test)
  boost_graph_parallel_test(distributed_page_rank_test)
  boost_graph_parallel_test(distributed_csr_test)
  boost_graph_parallel_test(distributed_dfs_test)
  boost_graph_parallel_test(distributed_graph_coloring_test)
  boost_graph_parallel_test(distributed_mst_test)
  boost_graph_parallel_test(distributed_strong_components_test)
  boost_graph_parallel_test(hohberg_biconnected_components_test)
  boost_graph_parallel_test(mesh_generator_test ARGS 1000 1000 1 0)
  boost_graph_parallel_test(named_vertices_seq NUMPROCS 1)
  boost_graph_parallel_test(distributed_shortest_paths_test)
  boost_graph_parallel_test(distributed_csr_algorithm_test NUMPROCS 1)
  boost_graph_parallel_test(distributed_betweenness_centrality_test)
  boost_graph_parallel_test(distributed_dimacs_reader)
  boost_graph_parallel_test(distributed_rmat_cc_ps)
  boost_graph_parallel_test(distributed_rmat_cc)
  boost_graph_parallel_test(distributed_rmat_pagerank)
  boost_graph_parallel_test(distributed_st_connected_test)

  boost_add_executable(ssca 
    ssca.cpp
    OUTPUT_NAME tests/${BOOST_PROJECT_NAME}/ssca
    NO_INSTALL
    DEPENDS boost_graph_parallel boost_system
    COMPILE_FLAGS "${MPI_COMPILE_FLAGS}"
    LINK_FLAGS "${MPI_LINK_FLAGS}"
    LINK_LIBS ${MPI_LIBRARIES}
    SHARED_COMPILE_FLAGS "-DBOOST_MPI_DYN_LINK=1")

  boost_add_executable(algorithm_performance 
    algorithm_performance.cpp
    OUTPUT_NAME tests/${BOOST_PROJECT_NAME}/algorithm_performance
    NO_INSTALL
    DEPENDS boost_graph_parallel boost_system
    COMPILE_FLAGS "${MPI_COMPILE_FLAGS}"
    LINK_FLAGS "${MPI_LINK_FLAGS}"
    LINK_LIBS ${MPI_LIBRARIES}
    SHARED_COMPILE_FLAGS "-DBOOST_MPI_DYN_LINK=1")

  if(NOT MSVC)
    # Due to poor handling of partial ordering of class template partial 
    # specializations, we disable these features and tests on Visual C++.
    # Tested with Visual C++ 9 (Microsoft Visual Studio 2008); earlier
    # versions are no better.
    boost_graph_parallel_test(named_vertices_test)
    boost_graph_parallel_test(named_vertices_hash_test)
  endif(NOT MSVC)

endif(MPI_FOUND)
