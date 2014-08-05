#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(integer BOOST_DEPENDS test) 

boost_test_run(cstdint_test cstdint_test.cpp)
boost_test_run(integer_mask_test integer_mask_test.cpp DEPENDS boost_test_exec_monitor)
boost_test_run(integer_test integer_test.cpp DEPENDS boost_test_exec_monitor)
boost_test_run(integer_traits_test integer_traits_test.cpp DEPENDS boost_test_exec_monitor)
boost_test_run(static_log2_test static_log2_test.cpp DEPENDS boost_test_exec_monitor)
boost_test_run(static_min_max_test static_min_max_test.cpp DEPENDS boost_test_exec_monitor)
