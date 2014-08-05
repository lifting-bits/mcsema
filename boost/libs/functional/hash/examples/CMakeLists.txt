#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
#-------------------------------------------------------------------------
#-- Needed include directories for the tests
boost_additional_test_dependencies(config BOOST_DEPENDS test)
#-------------------------------------------------------------------------
boost_test_run(books)
boost_test_run(point)
boost_test_run(portable)


