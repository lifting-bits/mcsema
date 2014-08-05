boost_additional_test_dependencies(date_time BOOST_DEPENDS test bind)

# Core
boost_test_run(testint_adapter)
boost_test_run(testtime_resolution_traits)
boost_test_run(testwrapping_int)
boost_test_run(testconstrained_value)
boost_test_run(testgregorian_calendar)
boost_test_run(testgeneric_period)

set(DATE_TIME_COMPILE_FLAGS 
  "-DBOOST_DATE_TIME_POSIX_TIME_STD_CONFIG -DBOOST_DATE_TIME_STATIC_LINK -DBOOST_ALL_NO_LIB")
set(DATE_TIME_SHARED_COMPILE_FLAGS 
  "-DBOOST_DATE_TIME_POSIX_TIME_STD_CONFIG -DBOOST_ALL_DYN_LINK -DBOOST_ALL_NO_LIB")

# A macro that collects the common settings used to build a run test
# for the Date-Time library that links statically.
macro(date_time_static_test SUBDIR TESTNAME)
  boost_test_run(${TESTNAME}
    "${SUBDIR}/${TESTNAME}.cpp"
    DEPENDS boost_date_time STATIC
    COMPILE_FLAGS ${DATE_TIME_COMPILE_FLAGS})
endmacro(date_time_static_test)

# A macro that collects the common settings used to build a run test
# for the Date-Time library that links dynamically.
macro(date_time_shared_test SUBDIR TESTNAME)
  boost_test_run("${TESTNAME}_dll"
    "${SUBDIR}/${TESTNAME}.cpp"
    DEPENDS boost_date_time SHARED
    COMPILE_FLAGS ${DATE_TIME_SHARED_COMPILE_FLAGS})
endmacro(date_time_shared_test)

# Gregorian
date_time_static_test(gregorian testdate)
date_time_static_test(gregorian testdate_duration)
date_time_static_test(gregorian testgreg_durations)
date_time_static_test(gregorian testperiod)
date_time_static_test(gregorian testdate_iterator)
date_time_static_test(gregorian testformatters)
###  streaming
date_time_static_test(gregorian testdate_facet_new)
date_time_static_test(gregorian testdate_input_facet)
###
date_time_static_test(gregorian testgenerators)
date_time_static_test(gregorian testgreg_cal)
date_time_static_test(gregorian testgreg_day)     
date_time_static_test(gregorian testgreg_month)
date_time_static_test(gregorian testgreg_year)

date_time_shared_test(gregorian testdate)
date_time_shared_test(gregorian testdate_duration)
date_time_shared_test(gregorian testgreg_durations)
date_time_shared_test(gregorian testperiod)
date_time_shared_test(gregorian testdate_iterator)
date_time_shared_test(gregorian testformatters)
###  streaming
date_time_shared_test(gregorian testdate_facet_new)
date_time_shared_test(gregorian testdate_input_facet)
###
date_time_shared_test(gregorian testgenerators)
date_time_shared_test(gregorian testgreg_cal)
date_time_shared_test(gregorian testgreg_day)     
date_time_shared_test(gregorian testgreg_month)
date_time_shared_test(gregorian testgreg_year)

# POSIX Time
date_time_static_test(posix_time testfiletime_functions)
date_time_static_test(posix_time testlocal_adjustor)
date_time_static_test(posix_time testc_local_adjustor)
date_time_static_test(posix_time testclock)
date_time_static_test(posix_time testdst_rules)
date_time_static_test(posix_time testduration)
date_time_static_test(posix_time testiterator)
date_time_static_test(posix_time testparse_time)
date_time_static_test(posix_time testtime_period)
date_time_static_test(posix_time testtime)
date_time_static_test(posix_time testmicrosec_time_clock)
date_time_static_test(posix_time testtime_formatters)
date_time_static_test(posix_time testgreg_duration_operators)
### streaming
date_time_static_test(posix_time testtime_facet)
date_time_static_test(posix_time testtime_input_facet)
###

# Wide streaming
boost_test_run(testgreg_wstream
  "gregorian/testgreg_wstream.cpp"
  DEPENDS boost_date_time STATIC
  COMPILE_FLAGS "${DATE_TIME_COMPILE_FLAGS} -DUSE_DATE_TIME_PRE_1_33_FACET_IO")
boost_test_run(testtime_wstream
  "posix_time/testtime_wstream.cpp"
  DEPENDS boost_date_time STATIC
  COMPILE_FLAGS "${DATE_TIME_COMPILE_FLAGS} -DUSE_DATE_TIME_PRE_1_33_FACET_IO")

# Pre-1.33 facets
boost_test_run(testfacet_dll
  "gregorian/testfacet.cpp"
  DEPENDS boost_date_time SHARED
  COMPILE_FLAGS "${DATE_TIME_SHARED_COMPILE_FLAGS} -DUSE_DATE_TIME_PRE_1_33_FACET_IO")
# Note: This next test was commented out in the Jamfile.v2 because "it
# crashes on VC6 (cause unknown)"
boost_test_run(testparse_date_dll
  "gregorian/testparse_date.cpp"
  DEPENDS boost_date_time SHARED
  COMPILE_FLAGS "${DATE_TIME_SHARED_COMPILE_FLAGS} -DUSE_DATE_TIME_PRE_1_33_FACET_IO")
boost_test_run(testfacet
  "gregorian/testfacet.cpp"
  DEPENDS boost_date_time STATIC
  COMPILE_FLAGS "${DATE_TIME_COMPILE_FLAGS} -DUSE_DATE_TIME_PRE_1_33_FACET_IO")
boost_test_run(testparse_date
  "gregorian/testparse_date.cpp"
  DEPENDS boost_date_time STATIC
  COMPILE_FLAGS "${DATE_TIME_COMPILE_FLAGS} -DUSE_DATE_TIME_PRE_1_33_FACET_IO")
boost_test_run(teststreams
  "posix_time/teststreams.cpp"
  DEPENDS boost_date_time STATIC
  COMPILE_FLAGS "${DATE_TIME_COMPILE_FLAGS} -DUSE_DATE_TIME_PRE_1_33_FACET_IO")

# Local time
date_time_static_test(local_time testdst_transition_day_rule)
date_time_static_test(local_time testcustom_time_zone)
date_time_static_test(local_time testposix_time_zone)
date_time_static_test(local_time testwcustom_time_zone)
date_time_static_test(local_time testwposix_time_zone)

# we have to copy these into the binary dir because to make the 
# paths inside the tests match
if (NOT ${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  FILE(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/libs/date_time/data")
  execute_process(COMMAND cmake -E copy "${CMAKE_SOURCE_DIR}/libs/date_time/data/date_time_zonespec.csv" "${CMAKE_BINARY_DIR}/libs/date_time/data")
  FILE(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/libs/date_time/test/local_time")
  execute_process(COMMAND cmake -E copy "${CMAKE_SOURCE_DIR}/libs/date_time/test/local_time/poorly_formed_zonespec.csv" "${CMAKE_BINARY_DIR}/libs/date_time/test/local_time")
endif (NOT ${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})

date_time_static_test(local_time testtz_database)
date_time_static_test(local_time testlocal_time)
date_time_static_test(local_time testlocal_time_iterator)
date_time_static_test(local_time testlocal_time_period)
### streaming
date_time_static_test(local_time testlocal_time_facet)
date_time_static_test(local_time testlocal_time_input_facet)
###
date_time_static_test(local_time testclocks)


set(DATE_TIME_COMPILE_FLAGS 
  "-DBOOST_DATE_TIME_STATIC_LINK -DBOOST_ALL_NO_LIB -DUSE_DATE_TIME_PRE_1_33_FACET_IO")

# Serialization
 # xml archive tests
boost_test_run(testgreg_serialize_xml
  "gregorian/testgreg_serialize.cpp"
  DEPENDS boost_date_time boost_serialization STATIC
  COMPILE_FLAGS "${DATE_TIME_COMPILE_FLAGS} -DDATE_TIME_XML_SERIALIZE")
boost_test_run(testtime_serialize_xml_std_config
  "posix_time/testtime_serialize.cpp"
  DEPENDS boost_date_time boost_serialization STATIC
  COMPILE_FLAGS "${DATE_TIME_COMPILE_FLAGS} -DBOOST_DATE_TIME_POSIX_TIME_STD_CONFIG -DDATE_TIME_XML_SERIALIZE")
boost_test_run(testtime_serialize_xml
  "posix_time/testtime_serialize.cpp"
  DEPENDS boost_date_time boost_serialization STATIC
  COMPILE_FLAGS "${DATE_TIME_COMPILE_FLAGS} -DDATE_TIME_XML_SERIALIZE")

 # text archive tests
boost_test_run(testgreg_serialize
  "gregorian/testgreg_serialize.cpp"
  DEPENDS boost_date_time boost_serialization STATIC
  COMPILE_FLAGS "${DATE_TIME_COMPILE_FLAGS}")
boost_test_run(testgreg_serialize_dll
  "gregorian/testgreg_serialize.cpp"
  DEPENDS boost_date_time SHARED boost_serialization SHARED
  COMPILE_FLAGS "${DATE_TIME_SHARED_COMPILE_FLAGS}")
boost_test_run(testtime_serialize_std_config
  "posix_time/testtime_serialize.cpp"
  DEPENDS boost_date_time boost_serialization STATIC
  COMPILE_FLAGS "${DATE_TIME_COMPILE_FLAGS} -DBOOST_DATE_TIME_POSIX_TIME_STD_CONFIG")
boost_test_run(testtime_serialize
  "posix_time/testtime_serialize.cpp"
  DEPENDS boost_date_time boost_serialization STATIC
  COMPILE_FLAGS "${DATE_TIME_COMPILE_FLAGS}")

# Copyright (c) 2000-2005
# CrystalClear Software, Inc.
# Subject to the Boost Software License, Version 1.0. 
# (See accompanying file LICENSE-1.0 or 
# http://www.boost.org/LICENSE-1.0)
