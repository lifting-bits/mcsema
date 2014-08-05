#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(program_options BOOST_DEPENDS test)

set(PROGRAM_OPTIONS_LIBRARIES
  boost_program_options
  boost_test_exec_monitor)

set(BOOST_TEST_EXEC_MONITOR_SUFFIX "")
if (NOT BUILD_SINGLE_THREADED)
  set(BOOST_TEST_EXEC_MONITOR_SUFFIX "-mt")
endif()
set(BOOST_TEST_EXEC_MONITOR_SUFFIX "${BOOST_TEST_EXEC_MONITOR_SUFFIX}-static")
if (NOT BUILD_RELEASE)
  set(BOOST_TEST_EXEC_MONITOR_SUFFIX "${BOOST_TEST_EXEC_MONITOR_SUFFIX}-debug")
endif()

macro(program_options_test_run TESTNAME)
  boost_test_run(${TESTNAME} 
    STATIC
    DEPENDS boost_program_options boost_test_exec_monitor )
  boost_test_run("${TESTNAME}_dll"
    ${TESTNAME}.cpp
    SHARED
    DEPENDS boost_program_options 
            "boost_test_exec_monitor${BOOST_TEST_EXEC_MONITOR_SUFFIX}")
endmacro(program_options_test_run)

program_options_test_run(options_description_test) 
program_options_test_run(parsers_test)
program_options_test_run(variable_map_test)
program_options_test_run(cmdline_test)
program_options_test_run(positional_options_test)
program_options_test_run(unicode_test) 
program_options_test_run(winmain) 
