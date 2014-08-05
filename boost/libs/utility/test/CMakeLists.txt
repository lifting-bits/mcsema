#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(utility BOOST_DEPENDS test)

boost_test_run(addressof_fn_test ../addressof_fn_test.cpp)
boost_test_run(addressof_test ../addressof_test.cpp)
boost_test_run(addressof_test2 ../addressof_test2.cpp)
boost_test_run(assert_test ../assert_test.cpp)
boost_test_run(base_from_member_test ../base_from_member_test.cpp)
boost_test_run(binary_search_test ../binary_search_test.cpp)
boost_test_run(call_traits_test ../call_traits_test.cpp ARGS -u)
boost_test_compile_fail(checked_delete_test ../checked_delete_test.cpp)
boost_test_run(compressed_pair_test 
  ../compressed_pair_test 
  DEPENDS boost_test_exec_monitor)
boost_test_run(current_function_test ../current_function_test.cpp)
boost_test_run(iterators_test 
  ../iterators_test.cpp 
  DEPENDS boost_test_exec_monitor)
boost_test_run(next_prior_test DEPENDS boost_test_exec_monitor)
boost_test_compile_fail(noncopyable_test ../noncopyable_test.cpp)
boost_test_run(numeric_traits_test ../numeric_traits_test.cpp)
if (${CMAKE_SYSTEM} MATCHES "FreeBSD-.*")
boost_test_compile_fail("operators_test_compilerbug")
elseif(${CMAKE_SYSTEM} MATCHES "FreeBSD-.*")
boost_test_run(operators_test 
  ../operators_test.cpp
  DEPENDS boost_test_exec_monitor)
endif(${CMAKE_SYSTEM} MATCHES "FreeBSD-.*")
boost_test_compile(ref_ct_test ../ref_ct_test.cpp)
boost_test_run(ref_test 
  ../ref_test.cpp
  DEPENDS boost_test_exec_monitor)
boost_test_compile(result_of_test)
boost_test_run(shared_iterator_test ../shared_iterator_test.cpp)
boost_test_run(value_init_test ../value_init_test.cpp)
boost_test_compile_fail(value_init_test_fail1 
  ../value_init_test_fail1.cpp)
boost_test_compile_fail(value_init_test_fail2
  ../value_init_test_fail2.cpp)
boost_test_compile_fail(value_init_test_fail3
  ../value_init_test_fail3.cpp)
boost_test_run(verify_test ../verify_test.cpp)