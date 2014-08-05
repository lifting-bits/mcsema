#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(io BOOST_DEPENDS test)


boost_test_run(ios_state_unit_test DEPENDS boost_unit_test_framework)
boost_test_run(ios_state_test DEPENDS boost_test_exec_monitor)

