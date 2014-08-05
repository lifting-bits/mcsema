#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(thread BOOST_DEPENDS test )



set(TESTS 
test_thread
test_thread_id
test_hardware_concurrency
test_thread_move
test_thread_launching
test_thread_mf
test_move_function
test_mutex
test_condition_notify_one
test_condition_timed_wait_times_out
test_condition_notify_all
test_condition
test_tss
test_once
test_xtime
test_barrier
test_shared_mutex
test_shared_mutex_part_2
test_shared_mutex_timed_locks
test_lock_concept
test_generic_locks)

foreach (TEST ${TESTS})
  boost_test_run(${TEST} MULTI_THREADED DEPENDS boost_thread boost_unit_test_framework)
endforeach (TEST ${TESTS})

boost_test_compile_fail(no_implicit_move_from_lvalue_thread)
boost_test_compile_fail(no_implicit_assign_from_lvalue_thread)
