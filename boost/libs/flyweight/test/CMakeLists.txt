# Boost.Flyweight tests Jamfile
#
# Copyright 2006-2008 Joaquín M López Muñoz.
# Distributed under the Boost Software License, Version 1.0.
# (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)
#
# See http://www.boost.org/libs/flyweight for library home page.

find_package(Threads)

macro(flyweight_test testname)
  boost_test_run(${testname} 
    test_${testname}.cpp test_${testname}_main.cpp
    LINK_LIBS ${CMAKE_THREAD_LIBS_INIT})
endmacro()

foreach(test
    basic
    custom_factory
    init
    multictor
    no_locking
    no_tracking
    set_factory)

  flyweight_test(${test})

endforeach()

#
# test_assoc_cont_fact_main is irregularly named
#
boost_test_run(assoc_cont_factory
  test_assoc_cont_factory.cpp test_assoc_cont_fact_main.cpp
  LINK_LIBS ${CMAKE_THREAD_LIBS_INIT})

#
# this one involves a dll
#
boost_add_library(intermod_holder_dll 
  intermod_holder_dll.cpp
  COMPILE_FLAGS "-DBOOST_FLYWEIGHT_TEST_INTERMOD_HOLDER_DLL_SOURCE=1"
  NO_SINGLE_THREADED
  NO_STATIC
  NO_INSTALL
  )

boost_test_run(intermod_holder
  test_intermod_holder.cpp test_intermod_holder_main.cpp
  LINK_LIBS ${CMAKE_THREAD_LIBS_INIT}
  DEPENDS intermod_holder_dll)

