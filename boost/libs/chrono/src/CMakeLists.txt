#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
set (BOOST_CHRONO_EXTRA_SOURCES)
set (BOOST_CHRONO_LIBRARIES)

boost_add_library (chrono
  chrono.cpp
  process_cpu_clocks.cpp
  thread_clock.cpp

  SHARED_COMPILE_FLAGS "-DBOOST_CHRONO_DYN_LINK=1"
  STATIC_COMPILE_FLAGS "-DBOOST_CHRONO_STATIC_LINK=1"
)
