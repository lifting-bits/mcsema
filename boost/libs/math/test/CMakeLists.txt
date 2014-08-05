#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(math BOOST_DEPENDS test regex)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

boost_test_run(common_factor_test DEPENDS boost_unit_test_framework)
boost_test_run(octonion_test 
  ../octonion/octonion_test.cpp
  DEPENDS boost_unit_test_framework)
boost_test_run(quaternion_test 
  ../quaternion/quaternion_test.cpp
  DEPENDS boost_unit_test_framework)
boost_test_run(special_functions_test 
  ../special_functions/special_functions_test.cpp 
  DEPENDS boost_unit_test_framework)
boost_test_run(quaternion_multi_incl_test 
  ../quaternion/quaternion_mult_incl_test.cpp 
                 ../quaternion/quaternion_mi1.cpp
                 ../quaternion/quaternion_mi2.cpp
  DEPENDS boost_unit_test_framework)
foreach(mathtest

    complex_test
    hypot_test
    )

  boost_test_run(${mathtest} DEPENDS boost_test_exec_monitor)
endforeach()
  
