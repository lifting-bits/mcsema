#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#

add_definitions(-DBOOST_MPI_SOURCE=1)
include_directories(${MPI_INCLUDE_PATH})

boost_add_library(
  mpi
  broadcast.cpp
  communicator.cpp
  computation_tree.cpp
  content_oarchive.cpp
  environment.cpp
  exception.cpp
  graph_communicator.cpp
  group.cpp
  intercommunicator.cpp
  mpi_datatype_cache.cpp
  mpi_datatype_oarchive.cpp
  packed_iarchive.cpp
  packed_oarchive.cpp
  packed_skeleton_iarchive.cpp
  packed_skeleton_oarchive.cpp
  point_to_point.cpp
  request.cpp
  text_skeleton_oarchive.cpp
  timer.cpp
  DEPENDS boost_serialization
  COMPILE_FLAGS "${MPI_COMPILE_FLAGS}"
  LINK_FLAGS "${MPI_LINK_FLAGS}"
  LINK_LIBS ${MPI_LIBRARIES}
  SHARED_COMPILE_FLAGS "-DBOOST_MPI_DYN_LINK=1"
  )

if(PYTHON_FOUND)

  colormsg (GREEN "+-- Python available, enabling boost_mpi_python.")
  include_directories(${PYTHON_INCLUDE_PATH})

  boost_add_library(mpi_python
    
    python/serialize.cpp

    DEPENDS boost_python boost_mpi
    SHARED_COMPILE_FLAGS "-DBOOST_MPI_DYN_LINK=1 -DBOOST_MPI_PYTHON_DYN_LINK=1 -DBOOST_PYTHON_DYN_LINK=1"
    LINK_FLAGS ${MPI_LINK_FLAGS}
    LINK_LIBS ${MPI_LIBRARIES} ${PYTHON_LIBRARIES}
    NO_STATIC)

  boost_python_extension(mpi
    
    python/collectives.cpp
    python/py_communicator.cpp
    python/datatypes.cpp
    python/documentation.cpp
    python/py_environment.cpp
    python/py_nonblocking.cpp
    python/py_exception.cpp
    python/module.cpp
    python/py_request.cpp
    python/skeleton_and_content.cpp
    python/status.cpp
    python/py_timer.cpp

    DEPENDS boost_python boost_mpi
    SHARED_COMPILE_FLAGS "-DBOOST_MPI_DYN_LINK=1 -DBOOST_MPI_PYTHON_DYN_LINK=1 -DBOOST_PYTHON_DYN_LINK=1"
    LINK_FLAGS ${MPI_LINK_FLAGS}
    LINK_LIBS ${MPI_LIBRARIES} ${PYTHON_LIBRARIES})

else()
  colormsg(RED "+-- optional python bindings disabled since PYTHON_FOUND is false.")
endif()

