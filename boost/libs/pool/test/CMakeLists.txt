#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(pool BOOST_DEPENDS test)

boost_test_run(test_pool_alloc DEPENDS boost_test_exec_monitor)
