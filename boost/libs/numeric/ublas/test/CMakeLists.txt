#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
# Define features to test:
#  Value types: USE_FLOAT USE_DOUBLE USE_STD_COMPLEX
#  Proxies: USE_RANGE USE_SLICE
#  Storage types: USE_BOUNDED_ARRAY USE_UNBOUNDED_ARRAY
#  Vector types: USE_STD_VECTOR USE_BOUNDED_VECTOR
#  Matrix types: USE_MATRIX USE_BOUNDED_MATRIX USE_VECTOR_OF_VECTOR
#  Adaptors: USE_ADAPTOR

set(UBLAS_TESTSET_DEFINES
  "-DUSE_DOUBLE -DUSE_STD_COMPLEX -DUSE_RANGE -DUSE_SLICE -DUSE_UNBOUNDED_ARRAY -DUSE_STD_VECTOR -DUSE_BOUNDED_VECTOR -DUSE_MATRIX")

#  Sparse storage: USE_MAP_ARRAY USE_STD_MAP
#  Sparse vectors: USE_MAPPED_VECTOR USE_COMPRESSED_VECTOR USE_COORDINATE_VECTOR
#  Sparse matrices: USE_MAPPED_MATRIX USE_COMPRESSED_MATRIX USE_COORDINATE_MATRIX USE_MAPPED_VECTOR_OF_MAPPED_VECTOR USE_GENERALIZED_VECTOR_OF_VECTOR

set(UBLAS_TESTSET_SPARSE_DEFINES
  "-DUSE_DOUBLE -DUSE_STD_COMPLEX -DUSE_UNBOUNDED_ARRAY -DUSE_MAP_ARRAY -DUSE_STD_MAP -DUSE_MAPPED_VECTOR -DUSE_COMPRESSED_VECTOR -DUSE_COORDINATE_VECTOR -DUSE_MAPPED_MATRIX -DUSE_COMPRESSED_MATRIX -DUSE_COORDINATE_MATRIX")

# Definitions for uBLAS tests
add_definitions(-DBOOST_UBLAS_NO_EXCEPTIONS)
# TODO: <toolset>vacpp:<define>"BOOST_UBLAS_NO_ELEMENT_PROXIES"

#-------------------------------------------------------------------------
#-- Needed include directories for the tests
boost_additional_test_dependencies(numeric BOOST_DEPENDS test)
#-------------------------------------------------------------------------


boost_test_run(ublas_test1
  test1.cpp test11.cpp test12.cpp test13.cpp
  COMPILE_FLAGS "${UBLAS_TESTSET_DEFINES}")

boost_test_run(ublas_test2
  test2.cpp test21.cpp test22.cpp test23.cpp
  COMPILE_FLAGS "${UBLAS_TESTSET_DEFINES}")

boost_test_run(ublas_test3
  test3.cpp test31.cpp test32.cpp test33.cpp
  COMPILE_FLAGS "${UBLAS_TESTSET_SPARSE_DEFINES}")

boost_test_run(ublas_test4
  test4.cpp test42.cpp test43.cpp
  COMPILE_FLAGS "${UBLAS_TESTSET_DEFINES}")

boost_test_run(ublas_test5
  test5.cpp test52.cpp test53.cpp
  COMPILE_FLAGS "${UBLAS_TESTSET_DEFINES}")

boost_test_run(ublas_test6
  test6.cpp test62.cpp test63.cpp
  COMPILE_FLAGS "${UBLAS_TESTSET_DEFINES}")

# Test commented out because boost::interval does not behave like a scalar
# boost_test_run(test7
#   test7.cpp test71.cpp test72.cpp test73.cpp
#   COMPILE_FLAGS "-DBOOST_UBLAS_USE_INTERVAL ${UBLAS_TESTSET_DEFINES}")

boost_test_run(placement_new)

boost_test_run(test_lu)

boost_test_run(triangular_access
  triangular_access.cpp
  COMPILE_FLAGS "-DNOMESSAGES")

boost_test_run(triangular_layout 
  triangular_layout.cpp)


SET(test_compile_flags "-DEXTERNAL")
#-- Intel Compiler flags
IF( ${CMAKE_CXX_COMPILER} MATCHES "icpc" )
    SET(test_compile_flags "${test_compile_flags} -Xc")  
ENDIF( ${CMAKE_CXX_COMPILER} MATCHES "icpc" )

IF (APPLE)
    SET(test_compile_flags "${test_compile_flags} -fabi-version=0") 
ENDIF (APPLE)

boost_test_compile(concepts COMPILE_FLAGS "-DEXTERNAL")
