#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
boost_additional_test_dependencies (context BOOST_DEPENDS test)

set (CONTEXT_LIBRARIES
  boost_context
  boost_test_exec_monitor)

set (BOOST_TEST_EXEC_MONITOR_SUFFIX "")
if (NOT BUILD_SINGLE_THREADED)
  set (BOOST_TEST_EXEC_MONITOR_SUFFIX "-mt")
endif (NOT BUILD_SINGLE_THREADED)

set (BOOST_TEST_EXEC_MONITOR_SUFFIX "${BOOST_TEST_EXEC_MONITOR_SUFFIX}-static")
if (NOT BUILD_RELEASE)
  set (BOOST_TEST_EXEC_MONITOR_SUFFIX "${BOOST_TEST_EXEC_MONITOR_SUFFIX}-debug")
endif (NOT BUILD_RELEASE)

#
macro (context_test_run TESTNAME)
  boost_test_run (${TESTNAME} 
    STATIC
    DEPENDS boost_context boost_test_exec_monitor )
  boost_test_run ("${TESTNAME}_dll"
    ${TESTNAME}.cpp
    SHARED
    DEPENDS boost_context 
    "boost_test_exec_monitor${BOOST_TEST_EXEC_MONITOR_SUFFIX}")
endmacro (context_test_run)

#
set (TESTS 
  test_context.cpp
  )

#
context_test_(run_timer_test) 
