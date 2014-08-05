#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(polygon BOOST_DEPENDS test)


ADD_DEFINITIONS(-DBOOST_ALL_NO_LIB) # -DBOOST_POLYGON_STATIC_LINK

boost_test_run(gtl_boost_unit_test gtl_boost_unit_test.cpp)
