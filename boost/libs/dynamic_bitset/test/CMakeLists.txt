#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(dynamic_bitset BOOST_DEPENDS test config)


boost_test_run(dyn_bitset_unit_tests1 ../dyn_bitset_unit_tests1.cpp)
boost_test_run(dyn_bitset_unit_tests2 ../dyn_bitset_unit_tests2.cpp)
boost_test_run(dyn_bitset_unit_tests3 ../dyn_bitset_unit_tests3.cpp)
boost_test_run(dyn_bitset_unit_tests4 ../dyn_bitset_unit_tests4.cpp)
