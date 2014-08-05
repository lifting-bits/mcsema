#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
# Test library configuration
# add_definitions(-DBOOST_TEST_NO_AUTO_LINK=1)

# Compiler-specific configuration
set(BOOST_SHARED_COMPILE_FLAGS "")
if(MSVC)
  add_definitions(/EHac)
  set(BOOST_SHARED_COMPILE_FLAGS "${BOOST_SHARED_COMPILE_FLAGS} -wd4275")
endif(MSVC)

if (BORLAND)
  add_definitions(-w-8080)
endif(BORLAND)

boost_add_library(prg_exec_monitor 
  execution_monitor.cpp 
  debug.cpp 
  cpp_main.cpp 
  SHARED_COMPILE_FLAGS -DBOOST_TEST_DYN_LINK=1 ${BOOST_SHARED_COMPILE_FLAGS})

boost_add_library(test_exec_monitor
  compiler_log_formatter.cpp
  debug.cpp
  execution_monitor.cpp
  framework.cpp
  plain_report_formatter.cpp
  progress_monitor.cpp
  results_collector.cpp
  results_reporter.cpp
  test_main.cpp
  test_tools.cpp
  unit_test_log.cpp
  unit_test_main.cpp
  unit_test_monitor.cpp
  unit_test_parameters.cpp
  unit_test_suite.cpp
  xml_log_formatter.cpp
  xml_report_formatter.cpp
  NO_SHARED
  )

boost_add_library(unit_test_framework
    compiler_log_formatter.cpp
    debug.cpp
    exception_safety.cpp
    execution_monitor.cpp
    framework.cpp
    interaction_based.cpp
    logged_expectations.cpp
    plain_report_formatter.cpp
    progress_monitor.cpp
    results_collector.cpp
    results_reporter.cpp
    test_tools.cpp
    unit_test_log.cpp
    unit_test_main.cpp
    unit_test_monitor.cpp
    unit_test_parameters.cpp
    unit_test_suite.cpp
    xml_log_formatter.cpp
    xml_report_formatter.cpp
    SHARED_COMPILE_FLAGS -DBOOST_TEST_DYN_LINK=1 ${BOOST_SHARED_COMPILE_FLAGS}
  )

