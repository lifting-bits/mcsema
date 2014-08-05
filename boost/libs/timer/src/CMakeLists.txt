#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on http://github.com/pocb/boost
#----------------------------------------------------------------------------
#
set (BOOST_TIMER_EXTRA_SOURCES)
set (BOOST_TIMER_LIBRARIES)

boost_add_library (timer
  auto_timers_construction.cpp
  cpu_timer.cpp

  SHARED_COMPILE_FLAGS "-DBOOST_TIMER_DYN_LINK=1"
  STATIC_COMPILE_FLAGS "-DBOOST_TIMER_STATIC_LINK=1"
)
