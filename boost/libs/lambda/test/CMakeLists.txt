#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(lambda BOOST_DEPENDS test any)

boost_test_run(algorithm_test DEPENDS boost_test_exec_monitor)
boost_test_run(bind_tests_simple DEPENDS boost_test_exec_monitor)
boost_test_run(bind_tests_advanced DEPENDS boost_test_exec_monitor)
boost_test_run(bind_tests_simple_f_refs DEPENDS boost_test_exec_monitor)
boost_test_run(bll_and_function DEPENDS boost_test_exec_monitor)
boost_test_run(lambda_cast_test 
  cast_test.cpp DEPENDS boost_test_exec_monitor)
boost_test_run(constructor_tests DEPENDS boost_test_exec_monitor)
boost_test_run(control_structures DEPENDS boost_test_exec_monitor)
boost_test_run(exception_test DEPENDS boost_test_exec_monitor)
boost_test_run(extending_rt_traits DEPENDS boost_test_exec_monitor)
boost_test_run(is_instance_of_test DEPENDS boost_test_exec_monitor)
boost_test_run(member_pointer_test DEPENDS boost_test_exec_monitor)
boost_test_run(operator_tests_simple DEPENDS boost_test_exec_monitor)
boost_test_run(phoenix_control_structures DEPENDS boost_test_exec_monitor)
boost_test_run(switch_construct DEPENDS boost_test_exec_monitor)
