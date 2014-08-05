#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(range BOOST_DEPENDS test)

message(STATUS "libs/range/test: need -Wall -Wunused here when under gcc")
set( test_compile_flags "")
IF(CMAKE_COMPILER_IS_GNUCC)
  SET(test_compile_flags "-Wall -Wunused")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

boost_test_run(array DEPENDS boost_unit_test_framework COMPILE_FLAGS ${test_compile_flags})
boost_test_run(iterator_pair DEPENDS boost_unit_test_framework COMPILE_FLAGS ${test_compile_flags})
boost_test_run(std_container DEPENDS boost_unit_test_framework COMPILE_FLAGS ${test_compile_flags})
boost_test_run(string DEPENDS boost_unit_test_framework COMPILE_FLAGS ${test_compile_flags})
boost_test_run(iterator_range DEPENDS boost_unit_test_framework COMPILE_FLAGS ${test_compile_flags})
boost_test_run(sub_range DEPENDS boost_unit_test_framework COMPILE_FLAGS ${test_compile_flags})
boost_test_run(partial_workaround DEPENDS boost_unit_test_framework COMPILE_FLAGS ${test_compile_flags})
boost_test_run(algorithm_example DEPENDS boost_unit_test_framework COMPILE_FLAGS ${test_compile_flags})
boost_test_run(reversible_range DEPENDS boost_unit_test_framework COMPILE_FLAGS ${test_compile_flags})
boost_test_run(const_ranges DEPENDS boost_unit_test_framework COMPILE_FLAGS ${test_compile_flags})
boost_test_run(extension_mechanism DEPENDS boost_unit_test_framework COMPILE_FLAGS ${test_compile_flags})
