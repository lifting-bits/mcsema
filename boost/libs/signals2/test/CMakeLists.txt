#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
foreach(test
    connection_test
    dead_slot_test
    deconstruct_test
    deletion_test
    ordering_test
    regression_test
    shared_connection_block_test
    signal_n_test
    signal_test
    signal_type_test
    slot_compile_test
    trackable_test
    track_test
    )
  boost_test_run(${test} DEPENDS boost_test_exec_monitor)
endforeach()

boost_test_run(mutex_test DEPENDS boost_thread)
boost_test_run(threading_models_test DEPENDS boost_thread)
