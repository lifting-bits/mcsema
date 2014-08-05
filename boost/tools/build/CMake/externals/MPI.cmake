# Copyright (C) Troy Straszheim
#
# Distributed under the Boost Software License, Version 1.0. 
# See accompanying file LICENSE_1_0.txt or copy at 
#   http://www.boost.org/LICENSE_1_0.txt 
#
set(MPI_FIND_QUIETLY TRUE)
find_package(MPI)

boost_external_report(MPI INCLUDE_PATH COMPILE_FLAGS LINK_FLAGS LIBRARIES)
  
