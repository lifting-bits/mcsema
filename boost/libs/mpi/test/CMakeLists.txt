#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
if (MPI_FOUND)
message(STATUS "MPI Found")

boost_additional_test_dependencies(mpi BOOST_DEPENDS test )

include_directories(${MPI_INCLUDE_PATH})

# Declare a test for the Boost.MPI library, which may involve both
# building the test and executing it with varying numbers of
# processes.
#
#     boost_mpi_test(testname
#                    [source1 source2 ...]
#                    [ARGS arg1 arg2 ...]
#                    [SCHEDULE procs1 procs2 ...]
#
# testname is the name of the test. source1, source2, etc. are the
# source files that will be built and linked into the test
# executable. If no source files are provided, the file "testname.cpp"
# will be used instead.
macro(boost_mpi_test testname) 
  PARSE_ARGUMENTS(MPI_TEST "SCHEDULE;ARGS" "" ${ARGN})

  # Determine the test sources
  if (MPI_TEST_DEFAULT_ARGS)
    set(MPI_TEST_SOURCES ${MPI_TEST_DEFAULT_ARGS})
  else (MPI_TEST_DEFAULT_ARGS)
    set(MPI_TEST_SOURCES "${testname}.cpp")
  endif (MPI_TEST_DEFAULT_ARGS)

  # Build the test executable
  boost_add_executable(${testname} 
    ${MPI_TEST_SOURCES}
    OUTPUT_NAME tests/${PROJECT_NAME}/${testname}
    NO_INSTALL
    DEPENDS boost_mpi
    COMPILE_FLAGS "${MPI_COMPILE_FLAGS}"
    LINK_FLAGS "${MPI_LINK_FLAGS}"
    LINK_LIBS ${MPI_LIBRARIES}
    SHARED_COMPILE_FLAGS "-DBOOST_MPI_DYN_LINK=1")
  if (THIS_EXE_OKAY)
    if (NOT MPI_TEST_SCHEDULE)
      set(MPI_TEST_SCHEDULE 1 2 3 4 7 8 13 17)
    endif (NOT MPI_TEST_SCHEDULE)

    foreach(PROCS ${MPI_TEST_SCHEDULE})
      add_test("${PROJECT_NAME}::${testname}-${PROCS}"
        ${MPIEXEC}
        -n ${PROCS}
        ${EXECUTABLE_OUTPUT_PATH}/${CMAKE_CFG_INTDIR}/tests/${PROJECT_NAME}/${testname} 
        ${BOOST_TEST_ARGS}
        )
    endforeach(PROCS)
  endif (THIS_EXE_OKAY)
endmacro(boost_mpi_test)

boost_mpi_test(all_gather_test)
boost_mpi_test(all_reduce_test)
boost_mpi_test(all_to_all_test)
boost_mpi_test(broadcast_test SCHEDULE 2 17)
boost_mpi_test(graph_topology_test SCHEDULE 2 7 13)
boost_mpi_test(is_mpi_op_test SCHEDULE 1)
boost_mpi_test(nonblocking_test)
boost_mpi_test(reduce_test)
boost_mpi_test(ring_test SCHEDULE 2 3 4 7 8 13 17)
boost_mpi_test(scan_test)
boost_mpi_test(scatter_test)
boost_mpi_test(skeleton_content_test SCHEDULE 2 3 4 7 8 13 17)


endif (MPI_FOUND)