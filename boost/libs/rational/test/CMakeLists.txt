#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(gil BOOST_DEPENDS test)


boost_test_run(rational_example rational_example.cpp)
boost_test_run(rational_test 
  rational_test.cpp
  DEPENDS boost_unit_test_framework
  )
