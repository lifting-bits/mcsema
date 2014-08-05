#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(function BOOST_DEPENDS test lambda) 


boost_test_run(lib_function_test function_test.cpp)
boost_test_run(function_n_test)
boost_test_run(allocator_test)
boost_test_run(stateless_test)
boost_test_run(lambda_test)
boost_test_compile_fail(function_test_fail1)
boost_test_compile_fail(function_test_fail2)
boost_test_compile(function_30)
boost_test_run(function_arith_cxx98)
boost_test_run(function_arith_portable)
boost_test_run(sum_avg_cxx98)
boost_test_run(sum_avg_portable)
boost_test_run(mem_fun_cxx98)
boost_test_run(mem_fun_portable)
boost_test_run(std_bind_cxx98)
boost_test_run(std_bind_portable)
boost_test_run(function_ref_cxx98)
boost_test_run(function_ref_portable)
boost_test_run(contains_test)
boost_test_run(contains2_test)
