#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_add_library(
  system
  error_code.cpp
  SHARED_COMPILE_FLAGS "-DBOOST_SYSTEM_DYN_LINK=1"
  STATIC_COMPILE_FLAGS "-DBOOST_SYSTEM_STATIC_LINK=1"
  )

