#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(circular_buffer BOOST_DEPENDS test )


boost_test_run(base_test SINGLE_THREADED)
boost_test_run(space_optimized_test SINGLE_THREADED)
boost_test_run(soft_iterator_invalidation SINGLE_THREADED)
boost_test_compile(bounded_buffer_comparison)