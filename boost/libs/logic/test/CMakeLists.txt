#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(logic BOOST_DEPENDS test)


boost_test_run(tribool_test)
boost_test_run(tribool_rename_test)
boost_test_run(tribool_io_test)
