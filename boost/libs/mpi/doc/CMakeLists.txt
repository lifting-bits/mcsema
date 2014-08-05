#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_add_documentation(mpi.qbk
  HEADERS mpi_autodoc.xml 
          boost/mpi.hpp
          boost/mpi/allocator.hpp
          boost/mpi/collectives.hpp
          boost/mpi/collectives_fwd.hpp
          boost/mpi/communicator.hpp
          boost/mpi/config.hpp
          boost/mpi/datatype.hpp
          boost/mpi/datatype_fwd.hpp
          boost/mpi/environment.hpp
          boost/mpi/exception.hpp
          boost/mpi/graph_communicator.hpp
          boost/mpi/group.hpp
          boost/mpi/intercommunicator.hpp
          boost/mpi/nonblocking.hpp
          boost/mpi/operations.hpp
          boost/mpi/packed_iarchive.hpp
          boost/mpi/packed_oarchive.hpp
          boost/mpi/skeleton_and_content.hpp
          boost/mpi/skeleton_and_content_fwd.hpp
          boost/mpi/status.hpp
          boost/mpi/request.hpp
          boost/mpi/timer.hpp
          boost/mpi/python.hpp
  DOXYGEN_PARAMETERS
    MACRO_EXPANSION=YES
    EXPAND_ONLY_PREDEF=YES
    "PREDEFINED=BOOST_MPI_HAS_MEMORY_ALLOCATION= BOOST_MPI_HAS_NOARG_INITIALIZATION= MPI_VERSION=2 BOOST_MPI_DOXYGEN="
  )