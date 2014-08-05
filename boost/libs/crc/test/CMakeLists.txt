#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(crc BOOST_DEPENDS test random)

boost_test_run(crc_test crc_test.cpp)

