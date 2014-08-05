#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(preprocessor BOOST_DEPENDS test)


boost_test_compile(arithmetic)
boost_test_compile(array)
boost_test_compile(comparison)
boost_test_compile(control)
boost_test_compile(debug)
boost_test_compile(facilities)
boost_test_compile(iteration)
boost_test_compile(list)
boost_test_compile(logical)
boost_test_compile(repetition)
boost_test_compile(selection)
boost_test_compile(seq)
boost_test_compile(slot)
boost_test_compile(tuple)
