#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(interprocess BOOST_DEPENDS test thread date_time multi_index)


file(GLOB INTERPROCESS_TESTS *.cpp)
foreach(TEST ${INTERPROCESS_TESTS})
  get_filename_component(TEST ${TEST} NAME_WE)
  boost_test_run(${TEST} DEPENDS boost_thread MULTI_THREADED)
endforeach()