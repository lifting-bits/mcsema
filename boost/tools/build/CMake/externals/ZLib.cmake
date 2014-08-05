# Copyright (C) Troy Straszheim
#
# Distributed under the Boost Software License, Version 1.0. 
# See accompanying file LICENSE_1_0.txt or copy at 
#   http://www.boost.org/LICENSE_1_0.txt 
#
if(ZLIB_SOURCE)
  message(STATUS "")
  colormsg(HIRED "ZLIB_SOURCE is not supported by Boost.CMake")
  colormsg(RED "Install zlib and let cmake detect it") 
  colormsg(RED "or help cmake out by setting the relevant variables")
endif()

set(ZLIB_FIND_QUIETLY TRUE)

find_package(ZLIB)

boost_external_report(ZLib INCLUDE_DIR LIBRARIES)

  
