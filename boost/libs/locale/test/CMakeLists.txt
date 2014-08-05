#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
boost_additional_test_dependencies (locale BOOST_DEPENDS test)

set (LOCALE_LIBRARIES
  boost_locale
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
macro (locale_test_run TESTNAME)
  boost_test_run (${TESTNAME} 
    STATIC
    DEPENDS boost_locale boost_test_exec_monitor )
  boost_test_run ("${TESTNAME}_dll"
    ${TESTNAME}.cpp
    SHARED
    DEPENDS boost_locale 
    "boost_test_exec_monitor${BOOST_TEST_EXEC_MONITOR_SUFFIX}")
endmacro (locale_test_run)

#
set (TESTS 
  test_config.cpp
  test_utf.cpp
  test_date_time.cpp
  test_ios_prop.cpp
  test_codepage_converter.cpp
  test_codepage.cpp
  test_message.cpp
  test_generator.cpp
  test_collate.cpp
  test_convert.cpp
  test_boundary.cpp
  test_formatting.cpp
  test_icu_vs_os_timezone.cpp
  test_winapi_collate.cpp
  test_winapi_convert.cpp
  test_winapi_formatting.cpp
  test_posix_collate.cpp
  test_posix_convert.cpp
  test_posix_formatting.cpp
  test_std_collate.cpp
  test_std_convert.cpp
  test_std_formatting.cpp
  )

#
locale_test_(run_timer_test) 
