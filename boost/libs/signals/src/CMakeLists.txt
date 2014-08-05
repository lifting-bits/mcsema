#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
add_definitions(-DBOOST_SIGNALS_NO_LIB=1)

boost_add_library(
  signals 
  trackable.cpp connection.cpp named_slot_map.cpp signal_base.cpp slot.cpp
  SHARED_COMPILE_FLAGS "-DBOOST_SIGNALS_DYN_LINK=1"
  )
