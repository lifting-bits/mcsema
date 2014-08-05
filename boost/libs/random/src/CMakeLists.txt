#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
add_definitions(-DBOOST_DATE_TIME_NO_LIB=1)
boost_add_library(
  random
  random_device.cpp
  STATIC_COMPILE_FLAGS -DBOOST_DATE_TIME_STATIC_LINK
  SHARED_COMPILE_FLAGS -DBOOST_ALL_DYN_LINK=1
  )
