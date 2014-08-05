#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(signals BOOST_DEPENDS test optional)


boost_test_run(dead_slot_test DEPENDS boost_signals)
boost_test_run(deletion_test DEPENDS boost_signals)
boost_test_run(ordering_test DEPENDS boost_signals)
boost_test_run(signal_n_test DEPENDS boost_signals)
boost_test_run(signal_test DEPENDS boost_signals)
boost_test_run(trackable_test DEPENDS boost_signals)
