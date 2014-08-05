#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(algorithm BOOST_DEPENDS test)


boost_test_run(trim_test)
boost_test_run(conv_test)
boost_test_run(predicate_test)
boost_test_run(find_test)
boost_test_run(split_test)
boost_test_run(join_test)
boost_test_run(replace_test)
boost_test_run(regex_test DEPENDS boost_regex SHARED)

