#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(tuple BOOST_DEPENDS test)


boost_test_run(tuple_test_bench DEPENDS boost_test_exec_monitor)
boost_test_run(io_test DEPENDS boost_test_exec_monitor)
