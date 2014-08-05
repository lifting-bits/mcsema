# Copyright (C) Troy Straszheim
#
# Distributed under the Boost Software License, Version 1.0. 
# See accompanying file LICENSE_1_0.txt or copy at 
#   http://www.boost.org/LICENSE_1_0.txt 
#
set(BZip2_FIND_QUIETLY TRUE)
find_package(BZip2)
boost_external_report(BZip2 INCLUDE_DIR DEFINITIONS LIBRARIES)

  
