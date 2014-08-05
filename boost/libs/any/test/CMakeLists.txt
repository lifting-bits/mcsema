#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(any BOOST_DEPENDS test)

boost_test_run(any_test ../any_test.cpp)
boost_test_compile_fail(any_cast_cv_failed)

