#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(format BOOST_DEPENDS test)

boost_test_run(format_test1 DEPENDS boost_test_exec_monitor)
boost_test_run(format_test2 DEPENDS boost_test_exec_monitor)
boost_test_run(format_test3 DEPENDS boost_test_exec_monitor)
boost_test_run(format_test_wstring DEPENDS boost_test_exec_monitor)

